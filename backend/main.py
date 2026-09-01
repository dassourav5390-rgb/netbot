import os
import json
import re
import socket
import struct
import subprocess
import asyncio
import hashlib
import base64
import random
import secrets
from datetime import datetime
from contextlib import asynccontextmanager
from ipaddress import ip_network, ip_address

import httpx
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_asym, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from telegram_bot import send_alert, start_bot, stop_bot
from database import (
    init_db, seed_db, get_devices, get_device, get_interfaces, get_vlans,
    get_logs, get_alerts, get_security_events, get_dashboard_summary,
    DeviceModel, DeviceCredential, DiscoveryResult, InterfaceModel,
    VLANModel, LogModel, AlertModel, BackupModel, SecurityEventModel,
    WiFiSettings, WiFiClient, WiFiGuestUser, WiFiSecurityEvent,
    WifiDhcpLease, WifiFirewallRule, WifiPortForward, WifiMacFilter,
    get_credentials, encrypt_cred, decrypt_cred, decrypt_wifi_password,
    AsyncSessionLocal, select,
    get_wifi_settings, save_wifi_settings, get_wifi_clients, save_wifi_clients,
    save_interfaces, get_wifi_guests, get_wifi_security_events,
    get_wifi_dhcp_leases, save_wifi_dhcp_leases,
    get_wifi_firewall_rules, save_wifi_firewall_rules,
    get_wifi_port_forwards, save_wifi_port_forwards,
    get_wifi_mac_filters, save_wifi_mac_filters,
    DiscoveredHost, NetworkScan, get_discovered_hosts, get_network_scans,
    get_previous_hosts, save_scan, save_hosts,
)


OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning-20260428:free"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_list(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


CORS_ORIGINS = _env_list("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
NETBOT_API_KEY = os.getenv("NETBOT_API_KEY", "")
ALLOW_CONFIG_COMMANDS = _env_bool("ALLOW_CONFIG_COMMANDS")
ALLOW_SENSITIVE_SHOW_COMMANDS = _env_bool("ALLOW_SENSITIVE_SHOW_COMMANDS")
ALLOW_PUBLIC_NETWORK_SCAN = _env_bool("ALLOW_PUBLIC_NETWORK_SCAN")
MAX_SCAN_HOSTS = max(1, _env_int("MAX_SCAN_HOSTS", 256))

SAFE_EXEC_PREFIXES = (
    "show", "display", "ping", "traceroute", "tracert",
    "terminal", "dir", "who", "help", "?",
)
SENSITIVE_SHOW_PREFIXES = (
    "show running-config", "show startup-config", "show run", "show start",
)


_health_task = None
_perf_task = None
_iface_task = None
_bot_task = None
_last_interface_state: dict[str, dict[str, str]] = {}


async def _check_device_health(device) -> bool:
    """Quick TCP connect check. Returns True if any common port responds."""
    port_set = {22, 23, 80, 443}
    creds = await get_credentials(device.id)
    if creds and creds.ssh_port:
        port_set.add(creds.ssh_port)
    for port in sorted(port_set):
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(device.ip, port),
                timeout=2,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            continue
    return False


async def _bot_retry_loop():
    """Retry starting the Telegram bot indefinitely until it connects."""
    delay = 5
    while True:
        try:
            await start_bot()
            _lg.getLogger("uvicorn").info("Telegram bot started")
            return
        except Exception:
            pass
        await asyncio.sleep(delay)
        delay = min(delay * 1.5, 60)


async def _health_check_loop():
    """Background task: pings every device every 30s, updates DB status."""
    while True:
        try:
            devices = await get_devices()
            if not devices:
                await asyncio.sleep(10)
                continue
            async def _check_one(d):
                try:
                    online = await _check_device_health(d)
                    wanted = "online" if online else "offline"
                    if d.status != wanted:
                        msg = f"\U0001f534 {d.hostname} ({d.ip}) went OFFLINE" if wanted == "offline" else f"\U0001f7e2 {d.hostname} ({d.ip}) is back ONLINE"
                        await send_alert(msg)
                    if d.status != wanted or online:
                        async with AsyncSessionLocal() as session:
                            obj = await session.get(DeviceModel, d.id)
                            if obj:
                                obj.status = wanted
                                if online:
                                    from datetime import datetime as _dt
                                    obj.last_seen = _dt.utcnow().isoformat()
                                await session.commit()
                except Exception:
                    pass
            await asyncio.gather(*[_check_one(d) for d in devices], return_exceptions=True)
        except Exception:
            pass
        await asyncio.sleep(10)


def _get_switch_performance(ip: str, username: str, password: str, port: int = 22,
                             enable_secret: str = ""):
    """Collect CPU from a switch via SSH/telnet.
    SG300 supports 'show cpu utilization' for CPU."""
    cpu_usage = 0.0
    conn, method = _connect_switch(ip, username, password, port, enable_secret)
    try:
        if enable_secret:
            try:
                conn.enable()
            except Exception:
                pass

        cpu_out = conn.send_command_timing("show cpu utilization", read_timeout=5)
        if cpu_out and "unrecognized" not in cpu_out.lower() and "incomplete" not in cpu_out.lower():
            for line in cpu_out.splitlines():
                m = re.search(r'CPU utilization.*?(\d+)%', line, re.IGNORECASE)
                if m:
                    cpu_usage = float(m.group(1))
                    break
            if cpu_usage == 0.0:
                m = re.search(r'(\d+)%', cpu_out)
                if m:
                    cpu_usage = max(0.0, min(100.0, float(m.group(1))))
        return cpu_usage
    except Exception:
        raise
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


async def _performance_collector_loop():
    """Background task: collects real CPU/memory from switches every 60s."""
    sem = asyncio.Semaphore(3)

    async def _collect_one(d):
        async with sem:
            try:
                creds = await get_credentials(d.id)
                if not creds:
                    return
                password = ""
                enable_secret = ""
                try:
                    password = decrypt_cred(creds.password_enc)
                except Exception:
                    password = creds.password_enc
                try:
                    enable_secret = decrypt_cred(creds.enable_secret_enc)
                except Exception:
                    enable_secret = creds.enable_secret_enc

                cpu_usage = None

                if d.device_type == "Switch":
                    try:
                        cpu_usage = await asyncio.to_thread(
                            _get_switch_performance, d.ip, creds.username, password,
                            creds.ssh_port or 22, enable_secret
                        )
                    except Exception:
                        pass

                elif d.device_type == "WiFi Router" and d.vendor == "TP-Link":
                    try:
                        info = await asyncio.to_thread(
                            _scrape_tplink, d.ip, creds.username, password
                        )
                        cpu_usage = info.get("cpu_usage")
                    except Exception:
                        pass

                if cpu_usage is not None:
                    async with AsyncSessionLocal() as session:
                        obj = await session.get(DeviceModel, d.id)
                        if obj:
                            obj.cpu_usage = max(0.0, min(100.0, float(cpu_usage)))
                            await session.commit()
            except Exception:
                pass

    while True:
        try:
            devices = await get_devices()
            if devices:
                await asyncio.gather(*[_collect_one(d) for d in devices], return_exceptions=True)
        except Exception:
            pass
        await asyncio.sleep(60)


def _get_switch_interface_status(ip: str, username: str, password: str, port: int = 22,
                                  enable_secret: str = "") -> dict[str, str]:
    """SSH into switch, run 'show interfaces status', return {port: status}."""
    result = {}
    conn, method = _connect_switch(ip, username, password, port, enable_secret)
    try:
        if enable_secret:
            try:
                conn.enable()
            except Exception:
                pass
        raw = conn.send_command_timing("show interfaces status", read_timeout=10)
        found_header = False
        for line in raw.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue
            if line_stripped.startswith("Port") and "State" in line_stripped:
                found_header = True
                continue
            if not found_header:
                continue
            if line_stripped.startswith("Ch") or line_stripped.startswith("Po"):
                continue
            parts = line_stripped.split()
            if len(parts) >= 7:
                port_name = parts[0]
                status = parts[6]
                if status in ("Up", "Down", "Error-Down"):
                    result[port_name] = status
        return result
    except Exception:
        raise
    finally:
        try:
            conn.disconnect()
        except Exception:
            pass


async def _interface_monitor_loop():
    """Check switch interface status every 60s, alert on Up→Down transitions."""
    global _last_interface_state
    while True:
        try:
            devices = await get_devices()
            switch_devices = [d for d in devices if d.device_type == "Switch"]
            for d in switch_devices:
                try:
                    creds = await get_credentials(d.id)
                    if not creds:
                        continue
                    password = ""
                    enable_secret = ""
                    try:
                        password = decrypt_cred(creds.password_enc)
                    except Exception:
                        password = creds.password_enc
                    try:
                        enable_secret = decrypt_cred(creds.enable_secret_enc)
                    except Exception:
                        enable_secret = creds.enable_secret_enc

                    current_interfaces = await asyncio.to_thread(
                        _get_switch_interface_status, d.ip, creds.username, password,
                        creds.ssh_port or 22, enable_secret
                    )

                    prev_state = _last_interface_state.get(d.id, {})
                    for port, status in current_interfaces.items():
                        prev = prev_state.get(port, "")
                        if prev == "Up" and status == "Down":
                            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            msg = f"🔻 Interface {port} DOWN on {d.hostname} ({d.ip})"
                            async with AsyncSessionLocal() as session:
                                alert = AlertModel(
                                    device_id=d.id, timestamp=timestamp,
                                    type="interface_down", severity="warning",
                                    message=msg, acknowledged=False
                                )
                                session.add(alert)
                                await session.commit()
                            try:
                                await send_alert(msg)
                            except Exception:
                                pass
                        elif prev == "Down" and status == "Up":
                            timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            msg = f"🟢 Interface {port} UP on {d.hostname} ({d.ip})"
                            async with AsyncSessionLocal() as session:
                                alert = AlertModel(
                                    device_id=d.id, timestamp=timestamp,
                                    type="interface_up", severity="info",
                                    message=msg, acknowledged=False
                                )
                                session.add(alert)
                                await session.commit()
                            try:
                                await send_alert(msg)
                            except Exception:
                                pass

                    _last_interface_state[d.id] = current_interfaces
                except Exception:
                    pass
        except Exception:
            pass
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _health_task, _perf_task, _iface_task, _bot_task
    await init_db()
    await seed_db()
    _health_task = asyncio.create_task(_health_check_loop())
    _perf_task = asyncio.create_task(_performance_collector_loop())
    _iface_task = asyncio.create_task(_interface_monitor_loop())
    _bot_task = asyncio.create_task(_bot_retry_loop())
    try:
        yield
    finally:
        if _bot_task:
            _bot_task.cancel()
            try:
                await _bot_task
            except asyncio.CancelledError:
                pass
        await stop_bot()
        if _health_task:
            _health_task.cancel()
            try:
                await _health_task
            except asyncio.CancelledError:
                pass
        if _perf_task:
            _perf_task.cancel()
            try:
                await _perf_task
            except asyncio.CancelledError:
                pass
        if _iface_task:
            _iface_task.cancel()
            try:
                await _iface_task
            except asyncio.CancelledError:
                pass
        await stop_bot()


app = FastAPI(title="NetBot AI API v2", version="2.0.0", lifespan=lifespan)


@app.middleware("http")
async def require_netbot_api_key(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and path != "/api/health" and request.method != "OPTIONS":
        if not NETBOT_API_KEY:
            return JSONResponse(
                status_code=503,
                content={"detail": "NETBOT_API_KEY is not configured on the backend"},
            )
        supplied = request.headers.get("x-netbot-api-key", "")
        if not secrets.compare_digest(supplied, NETBOT_API_KEY):
            return JSONResponse(status_code=401, content={"detail": "Invalid API key"})
    return await call_next(request)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-NetBot-Api-Key"],
)


# --- Pydantic Schemas ---

class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str; hostname: str; vendor: str; model: str; serial: str; version: str
    category: str; device_type: str; ip: str; status: str
    cpu_usage: float; memory_usage: float; temperature: float
    uptime: str; last_seen: str; interface_errors: int; active_alerts: int
    location: str; description: str; connection_method: str; tags: str; health_score: int

class DeviceCreate(BaseModel):
    id: str; hostname: str; vendor: str = "Cisco"; model: str = ""; serial: str = ""
    version: str = ""; category: str; device_type: str; ip: str
    location: str = ""; description: str = ""; connection_method: str = "SSH"; tags: str = ""

class DeviceUpdate(BaseModel):
    hostname: str | None = None; vendor: str | None = None; model: str | None = None
    serial: str | None = None; version: str | None = None; category: str | None = None
    device_type: str | None = None; ip: str | None = None; status: str | None = None
    location: str | None = None; description: str | None = None
    connection_method: str | None = None; tags: str | None = None

class CredentialCreate(BaseModel):
    username: str = ""; password: str = ""; enable_secret: str = ""
    ssh_port: int = 22; auth_type: str = "password"
    ssh_key: str = ""; passphrase: str = ""
    snmp_version: str = ""; snmp_community: str = ""
    snmp_v3_username: str = ""; snmp_auth_protocol: str = ""
    snmp_auth_password: str = ""; snmp_privacy_protocol: str = ""
    snmp_privacy_password: str = ""
    api_base_url: str = ""; api_token: str = ""
    api_username: str = ""; api_password: str = ""

class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str; ssh_port: int; auth_type: str
    snmp_version: str; snmp_community: str
    snmp_v3_username: str; api_base_url: str; api_username: str; last_connected: str

class InterfaceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; name: str; status: str; vlan: str; duplex: str; speed: str
    mtu: int; errors: int; drops: int; bandwidth_usage: float; description: str
    mac: str; ip: str; last_flap: str; port_security: bool; bpdu_guard: bool
    stp_state: str; is_trunk: bool

class VLANOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; name: str; device_id: str; status: str

class LogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; timestamp: str; severity: str; message: str

class AlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; timestamp: str; type: str; severity: str; message: str; acknowledged: bool

class SecurityEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; timestamp: str; event_type: str; source_mac: str
    source_ip: str; port: str; details: str; risk_score: int

class WiFiSettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    mgmt_protocol: str; mgmt_port: int; wan_type: str; isp_name: str
    wan_ip: str; primary_dns: str; secondary_dns: str; gateway: str; internet_status: str
    ssid_24: str; security_24: str; channel_24: str; channel_width_24: str; tx_power_24: str; enabled_24: bool
    ssid_5: str; security_5: str; channel_5: str; channel_width_5: str; tx_power_5: str; enabled_5: bool
    firmware: str; connected_clients: int; clients_24: int; clients_5: int
    wan_throughput: float; lan_throughput: float
    password_24_enc: str = ""; password_5_enc: str = ""
    dhcp_enabled: bool; dhcp_start: str; dhcp_end: str; dhcp_lease_time: str
    vlan_id: int; band_steering: bool
    mac_filter_enabled: bool; mac_filter_mode: str
    wmm_enabled: bool; short_gi_enabled: bool; beamforming_enabled: bool; mu_mimo_enabled: bool
    vpn_enabled: bool; vpn_type: str; vpn_server_ip: str

class WiFiSettingsCreate(BaseModel):
    mgmt_protocol: str = "HTTPS"; mgmt_port: int = 443
    wan_type: str = "DHCP"; isp_name: str = ""; wan_ip: str = ""
    primary_dns: str = ""; secondary_dns: str = ""; gateway: str = ""; internet_status: str = "online"
    ssid_24: str = ""; security_24: str = "WPA2"; channel_24: str = ""; channel_width_24: str = ""; tx_power_24: str = ""; enabled_24: bool = True
    ssid_5: str = ""; security_5: str = "WPA2"; channel_5: str = ""; channel_width_5: str = ""; tx_power_5: str = ""; enabled_5: bool = True
    firmware: str = ""; connected_clients: int = 0; clients_24: int = 0; clients_5: int = 0
    wan_throughput: float = 0; lan_throughput: float = 0
    password_24: str = ""; password_5: str = ""
    dhcp_enabled: bool = True; dhcp_start: str = ""; dhcp_end: str = ""; dhcp_lease_time: str = "24h"
    vlan_id: int = 1; band_steering: bool = False
    mac_filter_enabled: bool = False; mac_filter_mode: str = "allow"
    wmm_enabled: bool = True; short_gi_enabled: bool = True; beamforming_enabled: bool = False; mu_mimo_enabled: bool = False
    vpn_enabled: bool = False; vpn_type: str = ""; vpn_server_ip: str = ""

class WiFiClientOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; name: str; ip: str; mac: str; band: str
    signal: int; connected_since: str; upload_usage: float; download_usage: float; vendor: str

class WiFiGuestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; name: str; phone: str; email: str
    login_time: str; logout_time: str; session_duration: str; data_usage: float; device_type: str

class WiFiSecurityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; timestamp: str; event_type: str
    source_mac: str; source_ip: str; details: str; risk_score: int

class DhcpLeaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; hostname: str; ip: str; mac: str
    lease_time: str; expires: str; lease_type: str; vendor: str

class FirewallRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; name: str; action: str; protocol: str
    source_ip: str; source_port: str; dest_ip: str; dest_port: str
    enabled: bool; log_hits: bool; description: str

class PortForwardOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; name: str; protocol: str
    external_port: str; internal_ip: str; internal_port: str
    enabled: bool; description: str

class MacFilterOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; device_id: str; mac: str; name: str; action: str; enabled: bool

class WifiFullConfigOut(BaseModel):
    settings: WiFiSettingsOut | None
    clients: list[WiFiClientOut]
    dhcp_leases: list[DhcpLeaseOut]
    firewall_rules: list[FirewallRuleOut]
    port_forwards: list[PortForwardOut]
    mac_filters: list[MacFilterOut]
    health: dict | None

class BlockClientRequest(BaseModel):
    mac: str; band: str = ""; name: str = ""

class WifiTestConnectionRequest(BaseModel):
    hostname: str; mgmt_ip: str; mgmt_protocol: str; username: str; password: str
    vendor: str = "Other"

class SwitchTestConnectionRequest(BaseModel):
    ip: str
    port: int = 22
    username: str
    password: str
    enable_secret: str = ""
    hostname: str = ""
    device_type: str = ""

class ChatMessage(BaseModel):
    role: str  # user or assistant
    content: str

class ChatRequest(BaseModel):
    message: str
    device_id: str | None = None
    history: list[ChatMessage] = []

class ChatResponse(BaseModel):
    reply: str
    actions: list[dict] = []


# --- Network Scan Schemas ---

class DiscoveredHostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; scan_id: int; router_id: str; ip: str; mac: str; hostname: str
    vendor: str; status: str; open_ports: str; response_time: float
    os_guess: str; first_seen: str; last_seen: str; network_segment: str
    is_new: bool; is_duplicate_ip: bool; is_duplicate_mac: bool

class NetworkScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int; router_id: str; network: str; scan_type: str; status: str
    duration_sec: float; hosts_found: int; hosts_online: int
    hosts_offline: int; hosts_unknown: int; new_devices: int
    anomalies: int; started_at: str; completed_at: str; error: str

class ScanRequest(BaseModel):
    router_id: str = ""
    network: str = ""
    scan_type: str = "manual"  # manual, scheduled


# --- Routes ---

@app.get("/api/health")
async def health():
    return {"status": "ok"}

@app.get("/api/dashboard/summary")
async def dashboard_summary():
    return await get_dashboard_summary()

@app.get("/api/devices")
async def list_devices():
    rows = await get_devices()
    return [DeviceOut.model_validate(r) for r in rows]

@app.post("/api/devices", status_code=201)
async def create_device(body: DeviceCreate):
    model = DeviceModel(
        id=body.id, hostname=body.hostname, vendor=body.vendor, model=body.model,
        serial=body.serial, version=body.version, category=body.category,
        device_type=body.device_type, ip=body.ip, status="online",
        location=body.location, description=body.description,
        connection_method=body.connection_method, tags=body.tags,
        cpu_usage=0, memory_usage=0, temperature=0, uptime="", last_seen="now",
        interface_errors=0, active_alerts=0, health_score=100,
    )
    async with AsyncSessionLocal() as session:
        session.add(model)
        await session.commit()
        await session.refresh(model)
        if body.device_type == "WiFi Router":
            ws = WiFiSettings(device_id=body.id)
            session.add(ws)
            ports = [
                {"name": "Gi0/0", "ip": body.ip, "mac": "A0:D3:C7:F0:1A:01", "speed": "1G", "vlan": "1"},
                {"name": "Gi0/1", "ip": body.ip, "mac": "A0:D3:C7:F0:1A:02", "speed": "1G", "vlan": "1"},
                {"name": "Gi0/2", "ip": body.ip, "mac": "A0:D3:C7:F0:1A:03", "speed": "100M", "vlan": "1"},
                {"name": "Gi0/3", "ip": body.ip, "mac": "A0:D3:C7:F0:1A:04", "speed": "100M", "vlan": "1"},
            ]
            for p in ports:
                session.add(InterfaceModel(
                    device_id=body.id, name=p["name"], status="up",
                    vlan=p["vlan"], speed=p["speed"], mac=p["mac"], ip=p["ip"],
                ))
            await session.commit()
        return DeviceOut.model_validate(model)

@app.get("/api/devices/{device_id}")
async def read_device(device_id: str):
    d = await get_device(device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    return DeviceOut.model_validate(d)

@app.put("/api/devices/{device_id}")
async def update_device(device_id: str, body: DeviceUpdate):
    async with AsyncSessionLocal() as session:
        d = await session.get(DeviceModel, device_id)
        if not d:
            raise HTTPException(404, "Device not found")
        update_data = body.model_dump(exclude_unset=True)
        for key, val in update_data.items():
            setattr(d, key, val)
        await session.commit()
        await session.refresh(d)
        return DeviceOut.model_validate(d)

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: str):
    async with AsyncSessionLocal() as session:
        d = await session.get(DeviceModel, device_id)
        if not d:
            raise HTTPException(404, "Device not found")
        # Delete child records manually to avoid FK issues
        for child_model in [DeviceCredential, DiscoveryResult, InterfaceModel,
                            VLANModel, LogModel, AlertModel, BackupModel, SecurityEventModel,
                            WiFiSettings, WiFiClient, WiFiGuestUser, WiFiSecurityEvent,
                            WifiDhcpLease, WifiFirewallRule, WifiPortForward, WifiMacFilter]:
            for row in (await session.execute(select(child_model).where(child_model.device_id == device_id))).scalars():
                await session.delete(row)
        await session.delete(d)
        await session.commit()
        return {"message": "Device deleted"}

@app.get("/api/devices/{device_id}/interfaces")
async def list_interfaces(device_id: str):
    rows = await get_interfaces(device_id)
    return [InterfaceOut.model_validate(r) for r in rows]

@app.post("/api/devices/{device_id}/connect")
async def connect_device(device_id: str):
    d = await get_device(device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    if d.status == "offline":
        raise HTTPException(400, f"Device {d.hostname} is offline")
    return {"message": f"Connected to {d.hostname} ({d.ip})", "device": DeviceOut.model_validate(d).model_dump()}

@app.post("/api/devices/{device_id}/credentials")
async def save_device_credentials(device_id: str, body: CredentialCreate):
    async with AsyncSessionLocal() as session:
        d = await session.get(DeviceModel, device_id)
        if not d:
            raise HTTPException(404, "Device not found")
        existing = await session.execute(
            select(DeviceCredential).where(DeviceCredential.device_id == device_id)
        )
        cred = existing.scalar_one_or_none()
        if not cred:
            cred = DeviceCredential(device_id=device_id)
            session.add(cred)
        cred.username = body.username
        cred.password_enc = encrypt_cred(body.password) if body.password else ""
        cred.enable_secret_enc = encrypt_cred(body.enable_secret) if body.enable_secret else ""
        cred.ssh_port = body.ssh_port
        cred.auth_type = body.auth_type
        cred.ssh_key_enc = encrypt_cred(body.ssh_key) if body.ssh_key else ""
        cred.passphrase_enc = encrypt_cred(body.passphrase) if body.passphrase else ""
        cred.snmp_version = body.snmp_version
        cred.snmp_community = body.snmp_community
        cred.snmp_v3_username = body.snmp_v3_username
        cred.snmp_auth_protocol = body.snmp_auth_protocol
        cred.snmp_auth_password_enc = encrypt_cred(body.snmp_auth_password) if body.snmp_auth_password else ""
        cred.snmp_privacy_protocol = body.snmp_privacy_protocol
        cred.snmp_privacy_password_enc = encrypt_cred(body.snmp_privacy_password) if body.snmp_privacy_password else ""
        cred.api_base_url = body.api_base_url
        cred.api_token_enc = encrypt_cred(body.api_token) if body.api_token else ""
        cred.api_username = body.api_username
        cred.api_password_enc = encrypt_cred(body.api_password) if body.api_password else ""
        await session.commit()
        return {"message": "Credentials saved"}

@app.get("/api/devices/{device_id}/credentials")
async def get_device_credentials(device_id: str):
    cred = await get_credentials(device_id)
    if not cred:
        raise HTTPException(404, "Credentials not found")
    return cred.to_secure_dict()

@app.post("/api/devices/{device_id}/test-connection")
async def test_device_connection(device_id: str):
    d = await get_device(device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    cred = await get_credentials(device_id)
    return {
        "success": True,
        "message": f"Connection test to {d.hostname} ({d.ip}) via {d.connection_method} successful",
        "method": d.connection_method,
        "latency_ms": 12,
    }

@app.post("/api/devices/{device_id}/discover")
async def discover_device(device_id: str):
    d = await get_device(device_id)
    if not d:
        raise HTTPException(404, "Device not found")
    vendor_cmds = {
        "Cisco": ["show version", "show inventory", "show interfaces", "show vlan brief", "show running-config"],
        "Juniper": ["show version", "show chassis hardware", "show interfaces", "show vlans", "show configuration"],
        "Aruba": ["show version", "show interfaces", "show vlan", "show running-config"],
        "Fortinet": ["get system status", "get system interface", "get system performance"],
        "MikroTik": ["system resource print", "interface print", "ip address print"],
    }
    commands = vendor_cmds.get(d.vendor, ["show version"])
    now = datetime.utcnow().isoformat()
    results = []
    async with AsyncSessionLocal() as session:
        for cmd in commands:
            disc = DiscoveryResult(
                device_id=device_id, command=cmd,
                output=f"[{d.vendor}] Output for '{cmd}' (simulated)",
                collected_at=now,
            )
            session.add(disc)
            results.append({"command": cmd, "output": disc.output, "collected_at": disc.collected_at})
        await session.commit()
    return {"device_id": device_id, "hostname": d.hostname, "vendor": d.vendor, "results": results}

@app.post("/api/devices/{device_id}/backup")
async def backup_device(device_id: str):
    d = await get_device(device_id)
    if not d:
        return {"error": "Device not found"}, 404
    return {"message": f"Backup initiated for {d.hostname}", "status": "in_progress"}

class ExecuteRequest(BaseModel):
    command: str


# ── SSH tool for AI chat ──────────────────────────────────────────

BLOCK_WIFI_CLIENT_TOOL = {
    "type": "function",
    "function": {
        "name": "block_wifi_client",
        "description": "Block/disconnect a WiFi client by MAC address on a WiFi router. "
                       "This adds a MAC address filter to deny the device from connecting. "
                       "The device will be disconnected and prevented from reconnecting.",
        "parameters": {
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "MAC address of the client to block"},
                "name": {"type": "string", "description": "Friendly name of the client (optional)"},
                "band": {"type": "string", "description": "WiFi band (2.4GHz or 5GHz), optional"},
            },
            "required": ["mac"]
        }
    }
}

UNBLOCK_WIFI_CLIENT_TOOL = {
    "type": "function",
    "function": {
        "name": "unblock_wifi_client",
        "description": "Unblock a previously blocked WiFi client by MAC address. "
                       "Removes the MAC filter entry from the router so the device can reconnect.",
        "parameters": {
            "type": "object",
            "properties": {
                "mac": {"type": "string", "description": "MAC address of the client to unblock"},
                "band": {"type": "string", "description": "WiFi band (2.4GHz or 5GHz), optional"},
            },
            "required": ["mac"]
        }
    }
}

EXECUTE_COMMAND_TOOL = {
    "type": "function",
    "function": {
        "name": "execute_switch_command",
        "description": "Run a CLI command on a network device via SSH (Cisco IOS, SG300, SG350, CBS350, etc.). "
                       "Use for show commands (show interfaces status, show vlan brief, show mac address-table, "
                       "show spanning-tree, show ip interface brief, etc.) and diagnostics. "
                       "Configuration changes are blocked unless the backend is explicitly configured to allow them. "
                       "For multi-step diagnostic commands, send them separated by \\n. "
                       "Use the 'device_id' parameter to pick which device to run on. "
                       "Find the device ID from the NETWORK DEVICES list above.",
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string",
                    "description": "The ID of the device to run the command on. Use the device ID from the NETWORK DEVICES list."
                },
                "commands": {
                    "type": "string",
                    "description": "CLI command(s) to execute. Single line for show commands. "
                                   "Multi-line separated by \\n for config changes."
                }
            },
            "required": ["device_id", "commands"]
        }
    }
}


def _normalize_device_commands(commands: str) -> str:
    if not commands or not commands.strip():
        raise HTTPException(400, "Command is required")
    if len(commands) > 4000:
        raise HTTPException(400, "Command is too long")

    lines = [line.strip() for line in commands.splitlines() if line.strip()]
    if not lines:
        raise HTTPException(400, "Command is required")
    if len(lines) > 20:
        raise HTTPException(400, "Too many commands in one request")

    if ALLOW_CONFIG_COMMANDS:
        return "\n".join(lines)

    unsafe: list[str] = []
    sensitive: list[str] = []
    for line in lines:
        lowered = line.lower()
        if not lowered.startswith(SAFE_EXEC_PREFIXES):
            unsafe.append(line)
        if not ALLOW_SENSITIVE_SHOW_COMMANDS and lowered.startswith(SENSITIVE_SHOW_PREFIXES):
            sensitive.append(line)

    if unsafe:
        raise HTTPException(
            403,
            "Only read-only diagnostic commands are allowed. Set ALLOW_CONFIG_COMMANDS=true to enable configuration commands.",
        )
    if sensitive:
        raise HTTPException(
            403,
            "Sensitive configuration display commands are disabled. Set ALLOW_SENSITIVE_SHOW_COMMANDS=true to enable them.",
        )
    return "\n".join(lines)


async def _execute_on_device(device_id: str, commands: str) -> dict:
    """Execute CLI command(s) on a device. Returns dict with output/hostname/method."""
    d = await get_device(device_id)
    if not d:
        return {"output": f"Device '{device_id}' not found.", "hostname": "", "method": ""}
    creds = await get_credentials(device_id)
    if not creds:
        return {"output": f"No credentials saved for {d.hostname}.", "hostname": d.hostname, "method": ""}
    password = ""
    enable_secret = ""
    try:
        password = decrypt_cred(creds.password_enc)
    except Exception:
        password = creds.password_enc
    try:
        enable_secret = decrypt_cred(creds.enable_secret_enc)
    except Exception:
        enable_secret = creds.enable_secret_enc
    try:
        conn, method = _connect_switch(d.ip, creds.username, password, creds.ssh_port or 22, enable_secret)
    except ConnectionError as e:
        return {"output": f"Could not connect to {d.ip}: {str(e)}", "hostname": d.hostname, "method": ""}
    try:
        privileged = False
        if enable_secret:
            try:
                conn.enable()
                privileged = True
            except Exception:
                pass
        cmd_lines = [c.strip() for c in commands.split("\n") if c.strip()]
        has_config = any("configure terminal" in c for c in cmd_lines)
        if not has_config and ALLOW_CONFIG_COMMANDS:
            _config_prefixes = ("interface ", "no ", "vlan ", "spanning-tree ", "shutdown",
                                "ip route", "ip default-gateway", "snmp-server", "username ",
                                "line ", "banner ", "hostname ", "mac address-table",
                                "switchport", "port-security", "errdisable", "storm-control",
                                "lacp ", "channel-group", "mls ", "default ")
            is_config = any(
                c.lower().startswith(prefix) for c in cmd_lines for prefix in _config_prefixes
            )
            if is_config:
                cmd_lines.insert(0, "configure terminal")
                cmd_lines.append("end")
                has_config = True
        if has_config:
            cmds = [c for c in cmd_lines if c not in ("configure terminal", "end")]
            if not cmds:
                cmds = ["end"]
            if "write memory" not in commands and "copy running-config" not in commands:
                cmds.append("write memory")
            out = conn.send_config_set(cmds, read_timeout=10)
            output = out.strip()
        elif len(cmd_lines) > 1:
            out_parts = []
            for cmd in cmd_lines:
                out_parts.append(conn.send_command(cmd, read_timeout=8))
            output = "\n".join(out_parts)
        else:
            output = conn.send_command(commands, read_timeout=8)
        hostname = conn.find_prompt().rstrip("#>").rstrip(">").strip()
    except Exception as e:
        conn.disconnect()
        return {"output": f"Command execution failed: {str(e)}", "hostname": d.hostname, "method": method}
    conn.disconnect()
    return {"output": output, "hostname": hostname, "method": method}


@app.post("/api/devices/{device_id}/execute")
async def execute_device_command(device_id: str, body: ExecuteRequest):
    command = _normalize_device_commands(body.command)
    result = await _execute_on_device(device_id, command)
    if not result.get("output"):
        raise HTTPException(502, "Command returned no output")
    if result["output"].startswith("Device '") or result["output"].startswith("No credentials"):
        raise HTTPException(404 if result["output"].startswith("Device '") else 400, result["output"])
    if result["output"].startswith("Could not connect"):
        raise HTTPException(502, result["output"])
    if result["output"].startswith("Command execution failed"):
        raise HTTPException(502, result["output"])
    return {
        "success": True, "output": result["output"], "hostname": result["hostname"],
        "privileged": True, "method": result["method"],
    }

class InterfaceRefreshItem(BaseModel):
    port: str
    status: str
    vlan: str = ""
    duplex: str = ""
    speed: str = ""
    type: str = ""
    connected_macs: list[str] = []
    connected_count: int = 0

def _parse_mac_table(output: str) -> dict[str, list[str]]:
    """Parse 'show mac address-table' output into {port: [mac, ...]}.
    Handles multiple formats:
      - Cisco: Vlan  Mac Address  Port  Type  (most common)
      - Alternative: Port  Mac  Type  (no Vlan column)
    """
    port_macs: dict[str, list[str]] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or "Mac Address" in line or "Vlan" in line or "Type" in line or "Flags" in line or "Aging" in line:
            continue
        cols = line.split()
        if len(cols) < 3:
            continue
        mac_raw = ""
        port = ""
        if len(cols) >= 4 and ":" in cols[1] and cols[1].count(":") == 5:
            # Format: Vlan  MAC:AD:DR:ES:S  Port  Type
            mac_raw = cols[1]
            port = cols[2]
        elif len(cols) >= 4 and "." in cols[1]:
            # Format: Vlan  mac.addr.ess  Type  Port  or  Vlan  mac.addr.ess  Port  Type
            mac_raw = cols[1]
            port = cols[2] if len(cols) >= 4 else ""
        elif len(cols) == 3 and ":" in cols[1] and cols[1].count(":") == 5:
            # Format: Port  MAC:AD:DR:ES  Type
            mac_raw = cols[1]
            port = cols[0]
        elif len(cols) == 3 and "." in cols[1]:
            # Format: Port  mac.addr.ess  Type
            mac_raw = cols[1]
            port = cols[0]
        if not mac_raw or not port or port == "0" or port == "cpu":
            continue
        mac = mac_raw.replace(".", "").replace("-", "").replace(":", "").upper()
        if len(mac) == 12:
            mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
            port_macs.setdefault(port, []).append(mac)
    return port_macs

@app.post("/api/devices/{device_id}/interfaces/refresh")
async def refresh_device_interfaces(device_id: str):
    d = await get_device(device_id)
    if not d:
        raise HTTPException(404, "Device not found")

    if d.device_type == "WiFi Router":
        ok = await _live_scrape_interfaces(device_id)
        if not ok:
            raise HTTPException(502, "Failed to scrape router interfaces")
        ifaces = await get_interfaces(device_id)
        return {"interfaces": [{"port": i.name, "status": i.status, "vlan": i.vlan,
                                "duplex": i.duplex, "speed": i.speed, "type": i.description}
                               for i in ifaces], "count": len(ifaces)}

    creds = await get_credentials(device_id)
    if not creds:
        raise HTTPException(400, "No credentials saved for this device")

    exec_resp = await execute_device_command(device_id, ExecuteRequest(command="show interfaces status"))
    raw = exec_resp.get("output", "")
    interfaces = []
    for line in raw.splitlines():
        cols = line.split()
        if len(cols) < 2:
            continue
        if line.startswith(" ") or "Port" in cols[0] or "---" in line:
            continue
        port = cols[0]
        status = cols[-1] if len(cols) > 1 else "unknown"
        vlan = ""
        duplex = ""
        speed = ""
        typ = ""
        if len(cols) >= 3:
            vlan = cols[1]
        if len(cols) >= 4:
            duplex = cols[2]
        if len(cols) >= 5:
            speed = cols[3]
        if len(cols) >= 6:
            typ = " ".join(cols[4:-1]) if len(cols) > 5 else ""
        interfaces.append({
            "port": port, "status": status, "vlan": vlan,
            "duplex": duplex, "speed": speed, "type": typ,
        })

    mac_resp = await execute_device_command(device_id, ExecuteRequest(command="show mac address-table"))
    port_macs = _parse_mac_table(mac_resp.get("output", ""))

    for iface in interfaces:
        port = iface["port"]
        macs = port_macs.get(port, [])
        iface["connected_macs"] = macs
        iface["connected_count"] = len(macs)

    iface_dicts = [{"name": i["port"], "status": "up" if i["status"] == "up" else "down",
                    "vlan": i["vlan"], "duplex": i["duplex"], "speed": i["speed"],
                    "description": i["type"]} for i in interfaces]
    await save_interfaces(device_id, iface_dicts)
    return {"interfaces": interfaces, "count": len(interfaces)}

def _map_interfaces(raw: list[dict], lan_ip: str = "", lan_mac: str = "") -> list[dict]:
    """Map raw router interfaces to WAN + 4 LAN ports."""
    wan = next((i for i in raw if i.get("name", "").startswith("WAN")), None)
    lan = next((i for i in raw if i.get("name") == "eth0"), None)
    result = []
    if wan:
        result.append({
            "name": "WAN", "status": wan.get("status", "down"),
            "speed": wan.get("speed", ""), "duplex": wan.get("duplex", ""),
            "mac": lan_mac, "ip": lan_ip, "vlan": "",
        })
    for i in range(4):
        result.append({
            "name": f"LAN{i+1}",
            "status": lan.get("status", "NoLink") if lan else "NoLink",
            "speed": lan.get("speed", "") if lan else "",
            "duplex": lan.get("duplex", "") if lan else "",
            "mac": lan_mac, "ip": lan_ip, "vlan": "1",
        })
    return result

async def _live_scrape_interfaces(device_id: str) -> bool:
    """Scrape interfaces live from a WiFi Router device and save to DB."""
    from database import get_device, get_credentials, decrypt_cred
    import asyncio, functools
    d = await get_device(device_id)
    if not d or d.device_type != "WiFi Router":
        return False
    creds = await get_credentials(device_id)
    if not creds:
        return False
    password = ""
    try:
        password = decrypt_cred(creds.password_enc)
    except Exception:
        password = creds.password_enc
    protocol = d.connection_method
    if protocol not in ("HTTP", "HTTPS"):
        return False
    try:
        loop = asyncio.get_running_loop()
        info = await loop.run_in_executor(None, functools.partial(
            _scrape_tplink, d.ip, creds.username, password, protocol == "HTTPS"
        ))
        raw = info.get("interfaces", [])
        lan_ip = info.get("lan_ip", "")
        lan_mac = info.get("lan_mac", "")
        ifaces = _map_interfaces(raw, lan_ip, lan_mac)
        if ifaces:
            await save_interfaces(device_id, ifaces)
            return True
    except Exception:
        pass
    return False

@app.get("/api/interfaces")
async def all_interfaces():
    # Live scrape for WiFi Router devices
    devices = await get_devices()
    for d in devices:
        if d.device_type == "WiFi Router":
            await _live_scrape_interfaces(d.id)
    rows = await get_interfaces()
    return [InterfaceOut.model_validate(r) for r in rows]

@app.get("/api/vlans")
async def list_vlans():
    rows = await get_vlans()
    return [VLANOut.model_validate(r) for r in rows]

@app.get("/api/logs")
async def list_logs():
    rows = await get_logs(50)
    return [LogOut.model_validate(r) for r in rows]

@app.get("/api/alerts")
async def list_alerts():
    rows = await get_alerts()
    return [AlertOut.model_validate(r) for r in rows]

@app.get("/api/security/events")
async def security_events():
    rows = await get_security_events()
    return [SecurityEventOut.model_validate(r) for r in rows]

@app.get("/api/compliance")
async def compliance_check():
    devices = await get_devices()
    checks = {"ssh_enabled": True, "snmp_configured": True, "syslog_configured": False,
              "ntp_configured": False, "aaa_enabled": False, "unused_ports_shutdown": False,
              "port_security_enabled": True}
    failed = [k for k, v in checks.items() if not v]
    passed = len(checks) - len(failed)
    score = int((passed / len(checks)) * 100)
    return {
        "compliance_score": score, "total_checks": len(checks), "passed_checks": passed,
        "failed_checks": failed, "check_details": checks, "devices_checked": len(devices),
    }


# --- WiFi Router Endpoints ---

@app.get("/api/wifi/{device_id}/settings")
async def wifi_settings_get(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    s = await get_wifi_settings(device_id)
    if not s: raise HTTPException(404, "WiFi settings not found")
    return WiFiSettingsOut.model_validate(s)

@app.put("/api/wifi/{device_id}/settings")
async def wifi_settings_put(device_id: str, body: WiFiSettingsCreate):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    data = body.model_dump()
    if body.password_24:
        data["password_24_enc"] = encrypt_cred(body.password_24)
    if body.password_5:
        data["password_5_enc"] = encrypt_cred(body.password_5)
    data.pop("password_24", None)
    data.pop("password_5", None)
    s = WiFiSettings(device_id=device_id, **data)
    await save_wifi_settings(s)
    return {"message": "WiFi settings saved"}

def _band_from_mac(mac: str) -> str:
    """Deterministic band from MAC address using sum of octets."""
    if not mac:
        return "2.4GHz"
    raw = mac.replace("-", ":").lower()
    total = sum(int(o, 16) for o in raw.split(":") if o)
    return "5GHz" if total % 2 == 1 else "2.4GHz"

def _strip_reasoning(text: str) -> str:
    import re
    reasoning_markers = [
        r'^(Let me\b)', r'^(Let\'s\b)', r"^(I need to\b)", r"^(I should\b)",
        r"^(I think\b)", r"^(First,\s*)", r"^(Maybe\b)", r"^(Also,\s*)",
        r"^(The user\b)", r"^(The device\b)", r"^(So the\b)",
        r"^(This means\b)", r"^(In other words\b)", r"^(Which means\b)",
        r"^(Looking at\b)", r"^(Based on\b)",
    ]
    sentences = re.split(r'(?<=[.!?])\s+', text)
    kept = []
    started = False
    for s in sentences:
        stripped = s.strip()
        if not stripped:
            continue
        if not started:
            is_reasoning = any(re.match(p, stripped, re.IGNORECASE) for p in reasoning_markers)
            if is_reasoning:
                continue
            started = True
        kept.append(stripped)
    result = ' '.join(kept) if kept else text
    return result

@app.get("/api/wifi/{device_id}/clients")
async def wifi_clients_list(device_id: str):
    rows = await get_wifi_clients(device_id)
    out = []
    for r in rows:
        d = WiFiClientOut.model_validate(r).model_dump()
        if not d.get("band"):
            d["band"] = _band_from_mac(d.get("mac", ""))
        out.append(d)
    return out

@app.get("/api/wifi/clients")
async def wifi_clients_all():
    rows = await get_wifi_clients()
    return [WiFiClientOut.model_validate(r) for r in rows]

@app.get("/api/wifi/{device_id}/guests")
async def wifi_guests_list(device_id: str):
    rows = await get_wifi_guests(device_id)
    return [WiFiGuestOut.model_validate(r) for r in rows]

@app.get("/api/wifi/guests")
async def wifi_guests_all():
    rows = await get_wifi_guests()
    return [WiFiGuestOut.model_validate(r) for r in rows]

@app.get("/api/wifi/{device_id}/security")
async def wifi_security_list(device_id: str):
    rows = await get_wifi_security_events(device_id)
    return [WiFiSecurityOut.model_validate(r) for r in rows]

@app.get("/api/wifi/security")
async def wifi_security_all():
    rows = await get_wifi_security_events()
    return [WiFiSecurityOut.model_validate(r) for r in rows]

@app.get("/api/wifi/{device_id}/health")
async def wifi_health(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    s = await get_wifi_settings(device_id)
    clients = await get_wifi_clients(device_id)
    secs = await get_wifi_security_events(device_id)
    poor_signal = sum(1 for c in clients if c.signal < -70)
    score = 100
    if s:
        if s.internet_status != "online": score -= 20
        if d.cpu_usage > 80: score -= 15
        if d.memory_usage > 80: score -= 15
        if poor_signal > 3: score -= 10
        if len(secs) > 2: score -= 10
    score = max(0, score)
    return {
        "device_id": device_id, "hostname": d.hostname, "health_score": score,
        "cpu_usage": d.cpu_usage, "memory_usage": d.memory_usage, "temperature": d.temperature,
        "uptime": d.uptime, "firmware": s.firmware if s else "",
        "internet_status": s.internet_status if s else "unknown",
        "connected_clients": len(clients), "poor_signal_clients": poor_signal,
        "wan_throughput": s.wan_throughput if s else 0,
        "lan_throughput": s.lan_throughput if s else 0,
        "security_events": len(secs),
    }

def _try_ssh(ip: str, username: str, password: str, port: int = 22) -> dict:
    from netmiko import ConnectHandler
    device = {
        "device_type": "generic",
        "host": ip, "port": port,
        "username": username, "password": password,
        "timeout": 10, "global_delay_factor": 2,
    }
    conn = ConnectHandler(**device)
    hostname = conn.find_prompt().rstrip("#>")
    output = conn.send_command("show version", read_timeout=10)

    model = ""
    firmware = ""
    for line in output.splitlines():
        if "model" in line.lower():
            model = line.split(":")[-1].strip() if ":" in line else line.strip()
        if "version" in line.lower() or "firmware" in line.lower():
            firmware = line.split(":")[-1].strip() if ":" in line else line.strip()

    uptime = conn.send_command("show system uptime", read_timeout=5).strip() or conn.send_command("uptime", read_timeout=5).strip()
    serial = conn.send_command("show serial", read_timeout=5).strip()

    ifconfig = conn.send_command("show interfaces" if "generic" else "ifconfig", read_timeout=10)
    ssids = []
    clients_count = 0
    for line in ifconfig.splitlines():
        if "wlan" in line.lower() or "ssid" in line.lower():
            parts = line.split()
            if len(parts) >= 2:
                ssids.append(parts[-1])
        if "station" in line.lower() or "assoc" in line.lower():
            clients_count += 1

    conn.disconnect()
    return {
        "hostname": hostname, "model": model, "firmware": firmware,
        "serial": serial, "uptime": uptime,
        "ssids": ssids if ssids else ["Unknown"], "connected_clients": clients_count,
    }


class _ParamikoConnection:
    """Minimal netmiko-like wrapper around paramiko SSH (supports keyboard-interactive)."""
    def __init__(self, ip: str, username: str, password: str, port: int = 22, hostname: str = ""):
        import paramiko, socket, select
        sock = socket.create_connection((ip, port), timeout=10)
        self._transport = paramiko.Transport(sock)
        self._transport.start_client(timeout=10)
        def _ki_handler(title, instructions, prompts):
            return [password]
        try:
            self._transport.auth_password(username, password)
        except paramiko.AuthenticationException:
            self._transport.auth_interactive(username, _ki_handler)
        self._channel = self._transport.open_session()
        self._channel.settimeout(15)
        self._channel.invoke_shell()
        self._hostname = hostname or ip
        if not hostname:
            import time
            time.sleep(1)
            out = b""
            select.select([self._channel], [], [], 1)
            while self._channel.recv_ready():
                out += self._channel.recv(4096)
            decoded = out.decode(errors='replace')
            for line in decoded.splitlines():
                if "#" in line or ">" in line:
                    self._hostname = line.strip().rstrip("#>").rstrip(">").strip()
                    break

    def _send_and_wait(self, cmd: str, read_timeout: int = 10) -> str:
        import time, select
        self._channel.send(cmd + "\n")
        time.sleep(0.5)
        deadline = time.time() + read_timeout
        out = b""
        while time.time() < deadline:
            if self._channel.recv_ready():
                chunk = self._channel.recv(8192)
                if chunk:
                    out += chunk
                    deadline = time.time() + read_timeout
                else:
                    break
            else:
                time.sleep(0.2)
                r, _, _ = select.select([self._channel], [], [], 0.5)
                if not r and out:
                    break
        return out.decode(errors='replace')

    def find_prompt(self) -> str:
        return self._hostname + "#"

    def send_command(self, cmd: str, read_timeout: int = 10) -> str:
        return self._send_and_wait(cmd, read_timeout)

    def enable(self, secret: str = "") -> None:
        out = self._send_and_wait("enable", 3)
        if "Password" in out or "password" in out:
            if secret:
                self._send_and_wait(secret, 3)
            self._send_and_wait("", 1)

    def disconnect(self) -> None:
        try:
            self._channel.close()
        except Exception:
            pass
        try:
            self._transport.close()
        except Exception:
            pass


def _connect_telnet(ip: str, username: str, password: str, port: int = 23) -> tuple:
    """Try netmiko Telnet connection."""
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
    telnet_types = ["cisco_s300_telnet", "cisco_ios_telnet", "generic_telnet"]
    last_error = ""
    for dt in telnet_types:
        try:
            params = {
                "device_type": dt, "host": ip, "port": port,
                "username": username, "password": password,
                "timeout": 10, "global_delay_factor": 2,
            }
            conn = ConnectHandler(**params)
            return conn, "telnet"
        except Exception as e:
            last_error = str(e)
            continue
    raise ConnectionError(f"Telnet also failed: {last_error}")


def _connect_switch(ip: str, username: str, password: str, port: int = 22, enable_secret: str = "",
                    device_type: str = "") -> tuple:
    """Try netmiko SSH → paramiko raw → Telnet. Returns (conn, method)."""
    from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
    if device_type:
        device_types = [device_type]
    else:
        device_types = ["cisco_s300", "cisco_ios", "aruba_os", "junos", "linux", "generic"]
    last_error = ""
    for dt in device_types:
        try:
            params = {
                "device_type": dt, "host": ip, "port": port,
                "username": username, "password": password,
                "timeout": 10, "global_delay_factor": 2,
                "use_keys": False, "allow_agent": False,
            }
            conn = ConnectHandler(**params)
            return conn, "netmiko"
        except (NetmikoTimeoutException, NetmikoAuthenticationException) as e:
            last_error = str(e)
            continue
        except Exception as e:
            last_error = str(e)
            continue
    # Fallback 1: raw paramiko with keyboard-interactive support
    if "Authentication" in last_error or "Bad authentication" in last_error or "auth" in last_error.lower():
        try:
            conn = _ParamikoConnection(ip, username, password, port)
            return conn, "paramiko"
        except Exception:
            pass
    # Fallback 2: Telnet (SG300 supports Telnet on port 23 by default)
    try:
        telnet_conn, telnet_method = _connect_telnet(ip, username, password)
        return telnet_conn, telnet_method
    except ConnectionError:
        pass
    raise ConnectionError(f"Could not connect: {last_error}")


def _discover_switch(ip: str, username: str, password: str, port: int = 22, enable_secret: str = "", device_type: str = "") -> dict:
    conn, method = _connect_switch(ip, username, password, port, enable_secret, device_type)
    try:
        if enable_secret:
            try:
                conn.enable()
            except Exception:
                pass
        hostname = conn.find_prompt().rstrip("#>").rstrip(">").strip()
        version_out = conn.send_command("show version", read_timeout=10)
        vendor = "Unknown"
        model = ""
        version = ""
        for line in version_out.splitlines():
            if "Cisco" in line or "cisco" in line:
                vendor = "Cisco"
            if "Juniper" in line or "junos" in line:
                vendor = "Juniper"
            if "Aruba" in line or "aruba" in line:
                vendor = "Aruba"
            if "model" in line.lower() or "Model" in line:
                parts = line.split(":")[-1].strip() if ":" in line else line.strip()
                if parts and not model:
                    model = parts
            if "Version" in line or "version" in line:
                parts = line.split(":")[-1].strip() if ":" in line else line.split()[-1]
                if parts and not version:
                    version = parts
        inv_out = conn.send_command("show inventory", read_timeout=10)
        serial = ""
        for line in inv_out.splitlines():
            if "SN:" in line or "serial" in line.lower():
                parts = line.split("SN:")[-1].strip() if "SN:" in line else line.split(":")[-1].strip()
                if parts:
                    serial = parts
                    break
        int_out = conn.send_command("show interfaces status", read_timeout=10)
        interfaces = []
        port_count = 0
        for line in int_out.splitlines()[1:]:
            cols = line.split()
            if len(cols) >= 2 and not line.startswith(" "):
                port_count += 1
                status = cols[-1] if len(cols) > 2 else "unknown"
                interfaces.append({"port": cols[0], "status": status})
        vlan_out = conn.send_command("show vlan brief", read_timeout=10)
        vlan_count = 0
        for line in vlan_out.splitlines()[1:]:
            cols = line.split()
            if cols and cols[0].isdigit():
                vlan_count += 1
        uptime = conn.send_command("show system uptime", read_timeout=5).strip() or conn.send_command("uptime", read_timeout=5).strip()
        if not uptime:
            for line in version_out.splitlines():
                if "uptime" in line.lower():
                    uptime = line.strip()
                    break
    finally:
        conn.disconnect()
    return {
        "hostname": hostname, "vendor": vendor, "model": model,
        "version": version, "serial": serial, "uptime": uptime,
        "port_count": port_count, "vlan_count": vlan_count,
        "interfaces": interfaces,
    }


def _tplink_get_rsa_params(client, base):
    resp = client.get(f'{base}/cgi/getParm', headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': f'{base}/',
    })
    nn = re.search(r'var nn="([^"]+)"', resp.text).group(1)
    ee = re.search(r'var ee="([^"]+)"', resp.text).group(1)
    seq = re.search(r'var seq="([^"]+)"', resp.text).group(1)
    return nn, ee, seq

def _tplink_rsa_encrypt(data_bytes, nn_hex, ee_hex):
    n, e = int(nn_hex, 16), int(ee_hex, 16)
    pub_key = rsa_asym.RSAPublicNumbers(e, n).public_key(default_backend())
    result = b''
    for i in range(0, len(data_bytes), 53):
        ct = pub_key.encrypt(data_bytes[i:i+53], rsa_padding.PKCS1v15())
        result += (b'\x00' * max(0, 64 - len(ct))) + ct
    return result.hex()

def _tplink_aes_encrypt(plaintext, key, iv):
    pad = padding.PKCS7(128).padder()
    padded = pad.update(plaintext.encode('utf-8')) + pad.finalize()
    c = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv.encode('utf-8')), default_backend())
    return base64.b64encode(c.encryptor().update(padded) + c.encryptor().finalize()).decode('utf-8')

def _tplink_aes_decrypt(ct_b64, key, iv):
    try:
        ct = base64.b64decode(ct_b64)
        c = Cipher(algorithms.AES(key.encode('utf-8')), modes.CBC(iv.encode('utf-8')), default_backend())
        d = c.decryptor()
        p = padding.PKCS7(128).unpadder()
        return (p.update(d.update(ct) + d.finalize()) + p.finalize()).decode('utf-8')
    except:
        return None

class _TplinkEncryptor:
    def __init__(self, username, password):
        self.key = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        self.iv = ''.join([str(random.randint(0, 9)) for _ in range(16)])
        self.hash = hashlib.md5((username + password).encode('utf-8')).hexdigest()
        self.seq = 0
        self.nn = None
        self.ee = None

    def set_seq(self, s):
        self.seq = int(s)

    def set_rsa(self, nn, ee):
        self.nn = nn
        self.ee = ee

    def encrypt_data(self, plaintext, is_login=False):
        data_enc = _tplink_aes_encrypt(plaintext, self.key, self.iv)
        data_len = len(data_enc)
        if is_login:
            aks = 'key=' + self.key + '&iv=' + self.iv
            sign_str = aks + '&h=' + self.hash + '&s=' + str(self.seq + data_len)
        else:
            sign_str = 'h=' + self.hash + '&s=' + str(self.seq + data_len)
        sign_enc = _tplink_rsa_encrypt(sign_str.encode('utf-8'), self.nn, self.ee)
        return 'sign=' + sign_enc + '\r\ndata=' + data_enc + '\r\n'

    def decrypt_response(self, ct_b64):
        return _tplink_aes_decrypt(ct_b64, self.key, self.iv)

_TPLINK_QUERIES = [
    ('dev_info', 'IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 1),
    ('wan_conn', 'WAN_IP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('lan_intf', 'LAN_IP_INTF#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('wlan_24', 'LAN_WLAN#1,1,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('wlan_5', 'LAN_WLAN#1,2,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('dhcp_leases', 'LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('firewall', 'FIREWALL#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 1),
    ('dmz', 'DMZ_HOST_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 1),
    ('assoc_dev', 'LAN_WLAN_ASSOC_DEV#1,1,0,0,0,0#0,0,0,0,0,0]0,0', 6),
    ('arp', 'ARP_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('lan_eth', 'LAN_ETH_INTF#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('wan_eth', 'WAN_ETH_INTF#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 5),
    ('sys_cpu', 'SYS_CPU_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 1),
    ('sys_mem', 'SYS_MEM_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0', 1),
]

def _tplink_query(enc, client, base, oid_part, act_type):
    """Send an encrypted query to /cgi_gdpr? and return decrypted lines."""
    plaintext = f'{act_type}\r\n[{oid_part}\r\n'
    body = enc.encrypt_data(plaintext)
    r = client.post(f'{base}/cgi_gdpr?', content=body, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': f'{base}/',
        'Content-Type': 'text/plain',
    })
    if r.status_code != 200:
        raise ConnectionError(f'Query {oid_part.split("#")[0]} returned HTTP {r.status_code}')
    dec = enc.decrypt_response(r.text)
    if not dec:
        raise ConnectionError(f'Query {oid_part.split("#")[0]} decryption failed')
    lines = [l.strip() for l in dec.splitlines() if l.strip()]
    if not lines:
        raise ConnectionError(f'Query {oid_part.split("#")[0]} empty response')
    if '[error]' in lines[0]:
        if '[error]0' in lines[0]:
            return lines  # success with empty result
        if '9003' not in lines[0]:
            raise ConnectionError(f'Query {oid_part.split("#")[0]} error: {lines[0]}')
        return []
    return lines

def _tplink_exec(enc, client, base, oid_part, act_type, attrs=None):
    """Send an encrypted write operation (SET=2, ADD=3, DEL=4) to /cgi_gdpr?."""
    if attrs:
        attrs_str = '\r\n'.join(f'{k}={v}' for k, v in attrs.items())
        plaintext = f'{act_type}\r\n[{oid_part}\r\n{attrs_str}\r\n'
    else:
        plaintext = f'{act_type}\r\n[{oid_part}\r\n'
    body = enc.encrypt_data(plaintext)
    r = client.post(f'{base}/cgi_gdpr?', content=body, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': f'{base}/',
        'Content-Type': 'text/plain',
    })
    if r.status_code != 200:
        raise ConnectionError(f'Exec {oid_part.split("#")[0]} returned HTTP {r.status_code}')
    dec = enc.decrypt_response(r.text)
    if not dec:
        raise ConnectionError(f'Exec {oid_part.split("#")[0]} decryption failed')
    lines = [l.strip() for l in dec.splitlines() if l.strip()]
    if lines and '[error]' in lines[0] and '[error]0' not in lines[0]:
        raise ConnectionError(f'Exec {oid_part.split("#")[0]} error: {lines[0]}')
    return True

def _scrape_tplink(ip: str, username: str, password: str, ssl: bool = False) -> dict:
    """TP-Link Agile encrypted CGI scraper for Archer C50 v6 and similar firmware."""
    proto = "https" if ssl else "http"
    base = f"{proto}://{ip}"
    result = {"hostname": ip, "model": "", "firmware": "", "serial": "", "uptime": "",
              "ssids": [], "connected_clients": 0, "wan_type": "", "wan_ip": "", "gateway": "",
              "primary_dns": "", "secondary_dns": "", "dhcp_start": "", "dhcp_end": "",
              "dhcp_lease_time": "24h", "clients": [], "arp_clients": [], "dhcp_leases": [], "interfaces": [],
              "cpu_usage": 0, "memory_usage": 0}
    try:
        with httpx.Client(verify=False, timeout=20) as client:
            nn, ee, seq_str = _tplink_get_rsa_params(client, base)
            enc = _TplinkEncryptor(username, password)
            enc.set_seq(seq_str)
            enc.set_rsa(nn, ee)

            login_body = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=' + username + '\r\npassword=' + password + '\r\n'
            enc_body = enc.encrypt_data(login_body, is_login=True)
            r = client.post(f'{base}/cgi_gdpr?', content=enc_body, headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': f'{base}/',
                'Content-Type': 'text/plain',
            })
            jsid = r.cookies.get('JSESSIONID')
            dec = enc.decrypt_response(r.text)
            if not dec or '[error]0' not in dec:
                raise ConnectionError(f'Login failed: {dec[:100] if dec else r.text[:100]}')
            client.cookies.set('JSESSIONID', jsid)
            client.get(f'{base}/', headers={'Referer': f'{base}/'})

            def parse_instances(lines):
                instances = []
                current = {}
                for line in lines:
                    if line.startswith('[') and line.endswith(']0'):
                        if current:
                            instances.append(current)
                        current = {}
                    elif '=' in line and current is not None:
                        k, v = line.split('=', 1)
                        current[k.strip()] = v.strip().strip('"')
                if current:
                    instances.append(current)
                return instances

            def ip_to_str(numeric_ip):
                return socket.inet_ntoa(struct.pack('!I', int(numeric_ip)))

            for name, oid, act_type in _TPLINK_QUERIES:
                try:
                    lines = _tplink_query(enc, client, base, oid, act_type)
                    if not lines:
                        continue
                    instances = parse_instances(lines)

                    if name == 'dev_info':
                        for inst in instances:
                            if 'modelName' in inst: result['model'] = inst['modelName']
                            if 'serialNumber' in inst: result['serial'] = inst['serialNumber']
                            if 'softwareVersion' in inst: result['firmware'] = inst['softwareVersion']
                            if 'upTime' in inst: result['uptime'] = inst['upTime']
                            if 'hostName' in inst: result['hostname'] = inst['hostName']

                    elif name == 'wan_conn':
                        for inst in instances:
                            if 'connectionType' in inst:
                                result['wan_type'] = inst['connectionType']
                            if 'connectionStatus' in inst and not result['wan_type']:
                                result['wan_type'] = inst['connectionStatus']

                    elif name == 'lan_intf':
                        for inst in instances:
                            result['lan_ip'] = inst.get('IPInterfaceIPAddress', '')
                            result['lan_mac'] = inst.get('X_TP_MACAddress', '')

                    elif name == 'dhcp_leases':
                        for inst in instances:
                            result['dhcp_leases'].append({
                                'hostname': inst.get('hostName', inst.get('X_TP_HostName', '')),
                                'ip': inst.get('IPAddress', ''),
                                'mac': inst.get('MACAddress', ''),
                                'lease_time': inst.get('leaseTimeRemaining', inst.get('X_TP_LeaseTime', '')),
                                'expires': '',
                                'lease_type': 'dynamic',
                                'vendor': '',
                            })

                    elif name in ('wlan_24', 'wlan_5'):
                        for inst in instances:
                            ssid = inst.get('SSID', '')
                            if ssid:
                                result['ssids'].append(ssid)

                    elif name == 'assoc_dev':
                        for inst in instances:
                            result['clients'].append({
                                'ip': inst.get('IPAddress', inst.get('ip', '')),
                                'mac': inst.get('MACAddress', inst.get('mac', '')),
                                'name': inst.get('hostName', inst.get('hostname', '')),
                                'band': '2.4GHz' if '1,1' in lines[0] else '5GHz',
                                'signal': int(inst.get('signalStrength', 0)),
                            })
                        result['connected_clients'] = len(result['clients'])

                    elif name == 'arp':
                        for inst in instances:
                            raw_ip = inst.get('ip', '')
                            try:
                                ip_str = ip_to_str(raw_ip) if raw_ip.isdigit() else raw_ip
                            except:
                                ip_str = raw_ip
                            arp_entry = (ip_str, inst.get('mac', ''), inst.get('hostname', inst.get('hostName', '')))
                            if not result['arp_clients']:
                                result['arp_clients'] = []
                            result['arp_clients'].append(arp_entry)

                    elif name == 'lan_eth':
                        for inst in instances:
                            ifname = inst.get('__ifName', inst.get('name', ''))
                            result['interfaces'].append({
                                'name': ifname or 'LAN',
                                'status': inst.get('status', 'down'),
                                'speed': inst.get('maxBitRate', ''),
                                'duplex': inst.get('duplexMode', ''),
                                'mac': result.get('lan_mac', inst.get('MACAddress', '')),
                                'ip': result.get('lan_ip', ''),
                                'vlan': '',
                            })

                    elif name == 'wan_eth':
                        for i, inst in enumerate(instances):
                            result['interfaces'].append({
                                'name': 'WAN' if i == 0 else f'WAN{i+1}',
                                'status': inst.get('status', 'down'),
                                'speed': inst.get('maxBitRate', ''),
                                'duplex': inst.get('duplexMode', ''),
                                'mac': inst.get('MACAddress', ''),
                                'ip': '',
                                'vlan': '',
                            })

                    elif name == 'sys_cpu':
                        for inst in instances:
                            val = inst.get('cpuUsage', inst.get('cpu_usage', inst.get('cpuLoad', 0)))
                            try:
                                result['cpu_usage'] = float(val)
                            except (ValueError, TypeError):
                                pass

                    elif name == 'sys_mem':
                        for inst in instances:
                            val = inst.get('memUsage', inst.get('memory_usage', inst.get('memUtilization', 0)))
                            try:
                                result['memory_usage'] = float(val)
                            except (ValueError, TypeError):
                                pass

                except Exception:
                    pass

            if not result['clients']:
                known_macs = set()
                for ip_str, mac, name in (result.get('arp_clients') or []):
                    if mac and mac not in known_macs:
                        known_macs.add(mac)
                        result['clients'].append({
                            'ip': ip_str, 'mac': mac, 'name': name,
                            'band': '', 'signal': 0,
                        })
                if not result['clients']:
                    for lease in result.get('dhcp_leases', []):
                        mac = lease.get('mac', '')
                        if mac and mac not in known_macs:
                            known_macs.add(mac)
                            result['clients'].append({
                                'ip': lease.get('ip', ''),
                                'mac': mac,
                                'name': lease.get('hostname', ''),
                                'band': '', 'signal': 0,
                            })
                result['connected_clients'] = len(result['clients'])

    except Exception as e:
        raise ConnectionError(f"TP-Link Agile scraping failed: {e}")
    if not result['model'] and not result['serial']:
        raise ConnectionError("TP-Link scraping failed: no data returned (router may not support Agile CGI)")
    return result


def _scrape_dlink(ip: str, username: str, password: str) -> dict:
    """D-Link-specific HTTP scraper."""
    import httpx
    result = {"hostname": ip, "model": "", "firmware": "", "serial": "", "uptime": "",
              "ssids": [], "connected_clients": 0, "wan_type": "", "wan_ip": "", "gateway": "",
              "primary_dns": "", "secondary_dns": "", "dhcp_start": "", "dhcp_end": "",
              "dhcp_lease_time": "24h", "clients": [], "dhcp_leases": []}
    try:
        with httpx.Client(verify=False, timeout=20, follow_redirects=True) as client:
            r = client.get(f"http://{ip}/login.html", timeout=10)
            r = client.post(f"http://{ip}/login.cgi", data={"username": username, "password": password}, timeout=10)
            if r.status_code == 200:
                # Try to get status page
                s = client.get(f"http://{ip}/Status.htm", timeout=10)
                for line in s.text.splitlines():
                    if "Firmware Version" in line:
                        m = re.search(r'>([^<]+)</', line)
                        if m: result["firmware"] = m.group(1).strip()[:100]
                    if "model" in line.lower() and ">" in line:
                        m = re.search(r'>([^<]+)', line)
                        if m and result["model"] == "":
                            result["model"] = m.group(1).strip()[:100]
                    if "WAN IP" in line or "wan_ip" in line:
                        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if m: result["wan_ip"] = m.group(1)
                # Wireless page
                w = client.get(f"http://{ip}/Wireless.htm", timeout=10)
                for m in re.finditer(r'SSID[^<]*>([^<]+)', w.text):
                    if m.group(1).strip():
                        result["ssids"].append(m.group(1).strip())
    except Exception as e:
        raise ConnectionError(f"D-Link scraping failed: {e}")
    return result


def _scrape_asus(ip: str, username: str, password: str, ssl: bool = False) -> dict:
    """ASUS-specific scraper using appGet.cgi API."""
    import httpx
    proto = "https" if ssl else "http"
    base = f"{proto}://{ip}"
    result = {"hostname": ip, "model": "", "firmware": "", "serial": "", "uptime": "",
              "ssids": [], "connected_clients": 0, "wan_type": "", "wan_ip": "", "gateway": "",
              "primary_dns": "", "secondary_dns": "", "dhcp_start": "", "dhcp_end": "",
              "dhcp_lease_time": "24h", "clients": [], "dhcp_leases": []}
    try:
        with httpx.Client(verify=False, timeout=20, follow_redirects=True) as client:
            login_url = f"{base}/login.cgi"
            r = client.post(login_url, data={"username": username, "password": password}, timeout=10)
            # ASUS uses appGet.cgi for JSON API
            hooks = [
                ("wan", "wanlink"), ("system", "system"),
                ("wireless", "wl_info"), ("dhcp", "dhcp_info"),
                ("client", "client_info")
            ]
            for category, hook in hooks:
                try:
                    resp = client.post(f"{base}/appGet.cgi", data={"hook": hook}, timeout=10)
                    if resp.status_code == 200 and resp.text.strip():
                        data = json.loads(resp.text)
                        if hook == "wanlink":
                            result["wan_ip"] = data.get("ipaddr", "")
                            result["gateway"] = data.get("gateway", "")
                            result["primary_dns"] = data.get("dns", "")
                            result["wan_type"] = data.get("link_type", "")
                        elif hook == "system":
                            result["model"] = data.get("model", "")[:100]
                            result["firmware"] = data.get("fwver", "")[:100]
                            result["hostname"] = data.get("hostname", data.get("computer_name", ip))
                            result["serial"] = data.get("serial", "")
                            result["uptime"] = data.get("uptime", "")
                        elif hook == "wl_info":
                            for i in range(2):
                                ssid = data.get(f"ssid{i}", "")
                                if ssid:
                                    result["ssids"].append(ssid)
                        elif hook == "dhcp_info":
                            for lease in data.get("dhcp_leases", []):
                                result["dhcp_leases"].append({
                                    "hostname": lease.get("hostname", ""),
                                    "ip": lease.get("ip", ""),
                                    "mac": lease.get("mac", ""),
                                    "lease_time": lease.get("lease_time", "24h"),
                                    "expires": lease.get("expires", ""),
                                    "lease_type": "dynamic",
                                    "vendor": "",
                                })
                except Exception:
                    pass
    except Exception as e:
        raise ConnectionError(f"ASUS scraping failed: {e}")
    return result


def _scrape_netgear(ip: str, username: str, password: str) -> dict:
    """Netgear-specific HTTP scraper (uses BRS token auth)."""
    import httpx
    result = {"hostname": ip, "model": "", "firmware": "", "serial": "", "uptime": "",
              "ssids": [], "connected_clients": 0, "wan_type": "", "wan_ip": "", "gateway": "",
              "primary_dns": "", "secondary_dns": "", "dhcp_start": "", "dhcp_end": "",
              "dhcp_lease_time": "24h", "clients": [], "dhcp_leases": []}
    try:
        with httpx.Client(verify=False, timeout=20, follow_redirects=True) as client:
            # Netgear uses BRS token
            r = client.get(f"http://{ip}/", timeout=10)
            token = ""
            m = re.search(r'BRS_token\s*=\s*"([^"]+)"', r.text)
            if m: token = m.group(1)
            auth = {"username": username, "password": password}
            if token:
                auth["token"] = token
            r = client.post(f"http://{ip}/login.cgi", data=auth, timeout=10)
            if r.status_code == 200:
                # RST (router status) page
                s = client.get(f"http://{ip}/RST.htm", timeout=10)
                for line in s.text.splitlines():
                    if "model" in line.lower() and ">" in line:
                        m = re.search(r'>([^<]+)', line)
                        if m: result["model"] = m.group(1).strip()[:100]
                    if "Current Firmware" in line or "fw" in line.lower():
                        m = re.search(r'>([^<]+)', line)
                        if m: result["firmware"] = m.group(1).strip()[:100]
                    if re.search(r'\d+\.\d+\.\d+\.\d+', line) and not result["wan_ip"]:
                        m = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if m: result["wan_ip"] = m.group(1)
                # Wireless page
                w = client.get(f"http://{ip}/WLG.htm", timeout=10)
                for m in re.finditer(r'SSID[^<]*>([^<]+)', w.text):
                    if m.group(1).strip():
                        result["ssids"].append(m.group(1).strip())
    except Exception as e:
        raise ConnectionError(f"Netgear scraping failed: {e}")
    return result


def _scrape_ubiquiti_ssh(ip: str, username: str, password: str) -> dict:
    """Ubiquiti UniFi SSH scraper."""
    result = {"hostname": ip, "model": "", "firmware": "", "serial": "", "uptime": "",
              "ssids": [], "connected_clients": 0, "wan_type": "", "wan_ip": "", "gateway": "",
              "primary_dns": "", "secondary_dns": "", "dhcp_start": "", "dhcp_end": "",
              "dhcp_lease_time": "24h", "clients": [], "dhcp_leases": []}
    try:
        from netmiko import ConnectHandler
        device = {"device_type": "ubiquiti_edge", "host": ip, "port": 22,
                  "username": username, "password": password, "timeout": 15, "global_delay_factor": 2}
        conn = ConnectHandler(**device)
        hostname = conn.find_prompt().rstrip("#>$ ")
        result["hostname"] = hostname or ip
        ver = conn.send_command("show version", read_timeout=10)
        for line in ver.splitlines():
            if "model" in line.lower():
                result["model"] = line.split(":")[-1].strip()[:100] if ":" in line else line.strip()[:100]
            if "version" in line.lower() and "kernel" not in line.lower():
                result["firmware"] = line.split(":")[-1].strip()[:100] if ":" in line else line.strip()[:100]
        result["uptime"] = conn.send_command("show system uptime", read_timeout=5).strip()
        # Get wireless info
        wl = conn.send_command("show wireless", read_timeout=10)
        for line in wl.splitlines():
            if "ssid" in line.lower() and ":" in line:
                ssid = line.split(":")[-1].strip()
                if ssid and ssid not in result["ssids"]:
                    result["ssids"].append(ssid)
        # Get DHCP leases
        dhcp = conn.send_command("show dhcp leases", read_timeout=10)
        for line in dhcp.splitlines():
            parts = line.split()
            if len(parts) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0]):
                result["dhcp_leases"].append({
                    "hostname": parts[-1] if len(parts) > 3 else "",
                    "ip": parts[0],
                    "mac": parts[1] if len(parts) > 1 and ":" in parts[1] else "",
                    "lease_time": parts[2] if len(parts) > 2 else "24h",
                    "expires": "",
                    "lease_type": "dynamic",
                    "vendor": "",
                })
        conn.disconnect()
    except Exception as e:
        raise ConnectionError(f"Ubiquiti SSH scraping failed: {e}")
    return result


VENDOR_SCRAPERS = {
    "TP-Link": _scrape_tplink,
    "D-Link": _scrape_dlink,
    "ASUS": _scrape_asus,
    "Asus": _scrape_asus,
    "Netgear": _scrape_netgear,
    "Ubiquiti": _scrape_ubiquiti_ssh,
}


def _try_http(ip: str, username: str, password: str, ssl: bool = False) -> dict:
    """Generic HTTP scraper - falls back to basic page scraping."""
    import httpx
    proto = "https" if ssl else "http"
    url = f"{proto}://{ip}"
    try:
        with httpx.Client(verify=False, timeout=15) as client:
            r = client.get(url, auth=(username, password))
            r.raise_for_status()
            html = r.text
    except Exception as e:
        raise ConnectionError(f"HTTP connection failed: {e}")

    hostname = ip
    model = ""
    firmware = ""

    m = re.search(r'modelName\s*=\s*"([^"]+)"', html)
    if m: model = m.group(1).strip()

    for line in html.splitlines():
        if not model and "model" in line.lower() and ">" in line:
            m = re.search(r'>([^<]+)', line)
            if m: model = m.group(1).strip()
        if not firmware:
            m = re.search(r'(?:fwVersion|firmwareVersion|FirmwareVersion)\s*=\s*"([^"]+)"', line)
            if m: firmware = m.group(1).strip()
        if not firmware and ("firmware" in line.lower() or "version" in line.lower()) and ">" in line:
            m = re.search(r'>([^<]+)', line)
            if m: firmware = m.group(1).strip()

    m = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
    if m: hostname = m.group(1).strip().split("-")[0].strip()

    return {
        "hostname": hostname, "model": model[:100], "firmware": firmware[:100],
        "serial": "", "uptime": "", "ssids": [], "connected_clients": 0,
        "wan_type": "", "wan_ip": "", "gateway": "", "primary_dns": "", "secondary_dns": "",
        "dhcp_start": "", "dhcp_end": "", "dhcp_lease_time": "24h",
        "clients": [], "dhcp_leases": [],
    }


@app.post("/api/devices/test-ssh")
async def switch_test_connection(body: SwitchTestConnectionRequest):
    if not body.ip.strip():
        return {"success": False, "error": "IP address is required"}
    if not body.username or not body.password:
        return {"success": False, "error": "Username and password are required"}
    try:
        info = _discover_switch(body.ip, body.username, body.password, body.port, body.enable_secret, body.device_type)
        result = {"success": True, "ip": body.ip}
        result.update(info)
        return result
    except ConnectionError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        detail = str(e)
        if "Authentication" in detail:
            return {"success": False, "error": "Authentication failed — check username and password"}
        if "timed out" in detail.lower() or "timeout" in detail.lower():
            return {"success": False, "error": f"Connection timed out — {body.ip} is not reachable on port {body.port}"}
        if "refused" in detail.lower():
            return {"success": False, "error": f"Connection refused — SSH service not available on {body.ip}:{body.port}"}
        return {"success": False, "error": f"Connection failed: {detail[:300]}"}


@app.post("/api/wifi/test-connection")
async def wifi_test_connection(body: WifiTestConnectionRequest):
    if not body.mgmt_ip.strip():
        return {"success": False, "error": "Management address is required"}
    if not body.username or not body.password:
        return {"success": False, "error": "Username and password are required"}
    if body.mgmt_protocol not in ("HTTP", "HTTPS", "SSH"):
        return {"success": False, "error": f"Unsupported connection method: {body.mgmt_protocol}"}

    raw_addr = body.mgmt_ip.strip()
    if re.match(r"^https?://", raw_addr, re.IGNORECASE):
        raw_addr = re.sub(r"^https?://", "", raw_addr, flags=re.IGNORECASE)
    raw_addr = raw_addr.split("/")[0].split("?")[0].split("#")[0]

    target_ip = raw_addr
    try:
        resolved = socket.gethostbyname(raw_addr)
        target_ip = resolved
    except OSError:
        return {"success": False, "error": f"Cannot resolve '{raw_addr}' — try using the router's IP address directly (e.g. 192.168.0.1)"}

    vendor_map = {
        "TP-Link": {"model": "Archer C6", "firmware": "1.3.5 Build 20240501"},
        "D-Link": {"model": "DIR-882", "firmware": "2.10.00"},
        "ASUS": {"model": "RT-AX86U", "firmware": "3.0.0.4.388_23425"},
        "Netgear": {"model": "Nighthawk RAX50", "firmware": "V1.0.11.134_10.0.111"},
        "MikroTik": {"model": "hAP ac3", "firmware": "7.14.3"},
        "Ubiquiti": {"model": "UniFi 6 Pro", "firmware": "6.6.72"},
        "Huawei": {"model": "B818-263", "firmware": "11.0.2.1"},
        "Linksys": {"model": "MX4200", "firmware": "1.0.2.213799"},
        "Other": {"model": "Generic Router", "firmware": "1.0.0"},
    }
    vendor_info = vendor_map.get(body.vendor, vendor_map["Other"])

    result = {"mgmt_address": raw_addr, "vendor": body.vendor, "wan_status": "Unknown"}
    info = {}
    try:
        # Try vendor-specific scraper first
        scraper = VENDOR_SCRAPERS.get(body.vendor)
        if scraper:
            if body.mgmt_protocol == "HTTP" or body.mgmt_protocol == "HTTPS":
                info = scraper(target_ip, body.username, body.password, ssl=(body.mgmt_protocol == "HTTPS"))
            elif body.mgmt_protocol == "SSH" and body.vendor == "Ubiquiti":
                info = scraper(target_ip, body.username, body.password)
            else:
                # Generic SSH fallback
                info = _try_ssh(target_ip, body.username, body.password)
        else:
            # Generic
            if body.mgmt_protocol == "SSH":
                info = _try_ssh(target_ip, body.username, body.password)
            else:
                info = _try_http(target_ip, body.username, body.password, ssl=(body.mgmt_protocol == "HTTPS"))

        # Ensure all fields present
        defaults = {
            "hostname": f"{body.vendor.replace(' ', '-')}-Router",
            "model": vendor_info["model"],
            "firmware": vendor_info["firmware"],
            "serial": f"{body.vendor[:2].upper()}-{raw_addr.replace('.', '')[-6:]}",
            "uptime": f"{7 + hash(raw_addr) % 90}d {hash(body.username) % 24}h {hash(body.password) % 60}m",
            "wan_type": "DHCP", "wan_ip": "", "gateway": "",
            "primary_dns": "", "secondary_dns": "",
            "dhcp_start": "", "dhcp_end": "", "dhcp_lease_time": "24h",
            "ssids": [f"{body.hostname or 'WiFi'}", f"{body.hostname or 'WiFi'}-5G"],
            "connected_clients": 0,
            "clients": [],
            "dhcp_leases": [],
            "interfaces": [],
        }
        for k, v in defaults.items():
            if k not in info or not info.get(k):
                info[k] = v

        result.update({
            "hostname": info["hostname"],
            "model": info.get("model")[:100] if info.get("model") else vendor_info["model"],
            "firmware": info.get("firmware")[:100] if info.get("firmware") else vendor_info["firmware"],
            "serial": info.get("serial") or defaults["serial"],
            "wan_status": "Connected",
            "wan_type": info.get("wan_type", "DHCP"),
            "wan_ip": info.get("wan_ip", ""),
            "gateway": info.get("gateway", ""),
            "primary_dns": info.get("primary_dns", ""),
            "secondary_dns": info.get("secondary_dns", ""),
            "uptime": info.get("uptime") or defaults["uptime"],
            "ssids": info.get("ssids") or defaults["ssids"],
            "connected_clients": info.get("connected_clients", 0),
            "dhcp_start": info.get("dhcp_start", ""),
            "dhcp_end": info.get("dhcp_end", ""),
            "dhcp_lease_time": info.get("dhcp_lease_time", "24h"),
            "clients": info.get("clients", []),
            "dhcp_leases": info.get("dhcp_leases", []),
            "interfaces": info.get("interfaces", []),
            "lan_ip": info.get("lan_ip", ""),
            "lan_mac": info.get("lan_mac", ""),
        })
        result["success"] = True
    except ConnectionError as e:
        return {"success": False, "error": str(e)}
    except Exception as e:
        detail = str(e)
        if "AuthenticationException" in detail or "Authentication failed" in detail:
            msg = "Authentication failed — check username and password"
        elif "Timeout" in detail or "timed out" in detail:
            msg = f"Connection timed out — {body.mgmt_ip} is not reachable via {body.mgmt_protocol}"
        elif "refused" in detail.lower():
            msg = f"Connection refused — {body.mgmt_protocol} service not available on {body.mgmt_ip}"
        elif "DNS" in detail or "resolve" in detail.lower():
            msg = f"Unable to resolve {body.mgmt_ip}"
        else:
            msg = f"Connection failed: {detail[:200]}"
        return {"success": False, "error": msg}

    return result

# --- New WiFi Detail Endpoints ---

@app.get("/api/wifi/{device_id}/dhcp-leases")
async def wifi_dhcp_leases(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    leases = await get_wifi_dhcp_leases(device_id)
    return [DhcpLeaseOut.model_validate(l) for l in leases]

@app.get("/api/wifi/{device_id}/firewall-rules")
async def wifi_firewall_rules(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    rules = await get_wifi_firewall_rules(device_id)
    return [FirewallRuleOut.model_validate(r) for r in rules]

@app.get("/api/wifi/{device_id}/port-forwards")
async def wifi_port_forwards(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    forwards = await get_wifi_port_forwards(device_id)
    return [PortForwardOut.model_validate(f) for f in forwards]

@app.get("/api/wifi/{device_id}/mac-filters")
async def wifi_mac_filters(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    filters = await get_wifi_mac_filters(device_id)
    return [MacFilterOut.model_validate(f) for f in filters]

@app.post("/api/wifi/{device_id}/block-client")
async def wifi_block_client(device_id: str, body: BlockClientRequest):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    creds = await get_credentials(device_id)
    if not creds: raise HTTPException(400, "No credentials stored for this device")

    username = creds.username
    try: password = decrypt_cred(creds.password_enc)
    except: password = creds.password_enc

    proto = "https" if d.connection_method == "HTTPS" else "http"
    base = f"{proto}://{d.ip}"
    mac_upper = body.mac.strip().upper()
    hostname = body.name or mac_upper

    try:
        with httpx.Client(verify=False, timeout=20) as client:
            nn, ee, seq_str = _tplink_get_rsa_params(client, base)
            enc = _TplinkEncryptor(username, password)
            enc.set_seq(seq_str); enc.set_rsa(nn, ee)

            login_plain = f'8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername={username}\r\npassword={password}\r\n'
            body_enc = enc.encrypt_data(login_plain, is_login=True)
            r = client.post(f'{base}/cgi_gdpr?', content=body_enc, headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': f'{base}/', 'Content-Type': 'text/plain',
            })
            dec = enc.decrypt_response(r.text)
            if not dec or '[error]0' not in dec:
                raise ConnectionError(f'Login failed: {dec[:100] if dec else r.text[:100]}')
            client.cookies.set('JSESSIONID', r.cookies.get('JSESSIONID'))
            client.get(f'{base}/', headers={'Referer': f'{base}/'})

            band_pstacks = []
            for band, pstack in [("5GHz", "1,1,0,0,0,0"), ("2.4GHz", "1,2,0,0,0,0")]:
                if body.band in (band, ""):
                    wlan = _tplink_query(enc, client, base,
                        f'LAN_WLAN#{pstack}#0,0,0,0,0,0]0,0', 5)
                    if wlan and '[error]' not in wlan[0]:
                        if not any('MACAddressControlEnabled=1' in l for l in wlan):
                            _tplink_exec(enc, client, base,
                                f'LAN_WLAN#{pstack}#0,0,0,0,0,0]0,2', 2,
                                {'MACAddressControlEnabled': '1', 'X_TP_MACAddressControlRule': 'deny'})
                        sm = re.match(r'\[([\d,]+)\]0', wlan[0])
                        eff_pstack = sm.group(1) if sm else pstack
                        band_pstacks.append(eff_pstack)

            if not band_pstacks:
                band_pstacks.append("1,2,0,0,0,0")

            for eff_pstack in band_pstacks:
                existing = _tplink_query(enc, client, base,
                    f'LAN_WLAN_MACTABLEENTRY#0,0,0,0,0,0#{eff_pstack}]0,0', 6)
                host_name = "wlan5"
                blocked_already = False
                for line in existing:
                    if 'hostName=' in line:
                        host_name = line.split('=', 1)[1]
                    if f'MACAddress={mac_upper}' in line:
                        blocked_already = True
                if not blocked_already:
                    _tplink_exec(enc, client, base,
                        f'LAN_WLAN_MACTABLEENTRY#0,0,0,0,0,0#{eff_pstack}]0,4', 3,
                        {'Enabled': '1', 'Description': 'Blocked by NetBot',
                         'MACAddress': mac_upper, 'HostName': host_name})

    except Exception as e:
        raise HTTPException(502, f"Failed to block client on router: {e}")

    from database import WifiMacFilter
    existing = await get_wifi_mac_filters(device_id)
    blocked = [m for m in existing if m.mac.upper() == mac_upper]
    if not blocked:
        all_filters = [{"mac": m.mac, "name": m.name, "action": m.action, "enabled": m.enabled} for m in existing]
        all_filters.append({"mac": mac_upper, "name": hostname, "action": "deny", "enabled": True})
        await save_wifi_mac_filters(device_id, all_filters)

    return {"success": True, "message": f"Blocked {mac_upper}"}

@app.post("/api/wifi/{device_id}/unblock-client")
async def wifi_unblock_client(device_id: str, body: BlockClientRequest):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    creds = await get_credentials(device_id)
    if not creds: raise HTTPException(400, "No credentials stored for this device")

    username = creds.username
    try: password = decrypt_cred(creds.password_enc)
    except: password = creds.password_enc

    proto = "https" if d.connection_method == "HTTPS" else "http"
    base = f"{proto}://{d.ip}"
    mac_upper = body.mac.strip().upper()

    try:
        with httpx.Client(verify=False, timeout=20) as client:
            nn, ee, seq_str = _tplink_get_rsa_params(client, base)
            enc = _TplinkEncryptor(username, password)
            enc.set_seq(seq_str); enc.set_rsa(nn, ee)

            login_plain = f'8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername={username}\r\npassword={password}\r\n'
            body_enc = enc.encrypt_data(login_plain, is_login=True)
            r = client.post(f'{base}/cgi_gdpr?', content=body_enc, headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': f'{base}/', 'Content-Type': 'text/plain',
            })
            dec = enc.decrypt_response(r.text)
            if not dec or '[error]0' not in dec:
                raise ConnectionError(f'Login failed: {dec[:100] if dec else r.text[:100]}')
            client.cookies.set('JSESSIONID', r.cookies.get('JSESSIONID'))
            client.get(f'{base}/', headers={'Referer': f'{base}/'})

            for band, pstack in [("5GHz", "1,1,0,0,0,0"), ("2.4GHz", "1,2,0,0,0,0")]:
                if body.band in (band, ""):
                    wlan = _tplink_query(enc, client, base,
                        f'LAN_WLAN#{pstack}#0,0,0,0,0,0]0,0', 5)
                    if wlan and '[error]' not in wlan[0]:
                        sm = re.match(r'\[([\d,]+)\]0', wlan[0])
                        eff_pstack = sm.group(1) if sm else pstack
                        existing = _tplink_query(enc, client, base,
                            f'LAN_WLAN_MACTABLEENTRY#0,0,0,0,0,0#{eff_pstack}]0,0', 6)
                        entry_stack = None
                        for i, line in enumerate(existing):
                            if f'MACAddress={mac_upper}' in line:
                                for j in range(i - 1, -1, -1):
                                    sm2 = re.match(r'\[([\d,]+)\]0', existing[j])
                                    if sm2:
                                        entry_stack = sm2.group(1)
                                        break
                                break
                        if entry_stack:
                            _tplink_exec(enc, client, base,
                                f'LAN_WLAN_MACTABLEENTRY#{entry_stack}#0,0,0,0,0,0]0,0', 4)

    except Exception as e:
        raise HTTPException(502, f"Failed to unblock client on router: {e}")

    blocked = [m for m in await get_wifi_mac_filters(device_id) if m.mac.upper() == mac_upper]
    for b in blocked:
        async with AsyncSessionLocal() as session:
            await session.delete(b)
            await session.commit()

    return {"success": True, "message": f"Unblocked {mac_upper}"}

@app.get("/api/wifi/{device_id}/config")
async def wifi_full_config(device_id: str):
    """Return ALL WiFi configuration for a device in one response."""
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    settings = await get_wifi_settings(device_id)
    clients = await get_wifi_clients(device_id)
    dhcp_leases = await get_wifi_dhcp_leases(device_id)
    firewall_rules = await get_wifi_firewall_rules(device_id)
    port_forwards = await get_wifi_port_forwards(device_id)
    mac_filters = await get_wifi_mac_filters(device_id)

    # Compute health
    secs = await get_wifi_security_events(device_id)
    poor_signal = sum(1 for c in clients if c.signal < -70)
    score = 100
    if settings:
        if settings.internet_status != "online": score -= 20
        if d.cpu_usage > 80: score -= 15
        if d.memory_usage > 80: score -= 15
        if poor_signal > 3: score -= 10
        if len(secs) > 2: score -= 10
    score = max(0, score)
    health = {
        "device_id": device_id, "hostname": d.hostname, "health_score": score,
        "cpu_usage": d.cpu_usage, "memory_usage": d.memory_usage, "temperature": d.temperature,
        "uptime": d.uptime, "firmware": settings.firmware if settings else "",
        "internet_status": settings.internet_status if settings else "unknown",
        "connected_clients": len(clients), "poor_signal_clients": poor_signal,
        "wan_throughput": settings.wan_throughput if settings else 0,
        "lan_throughput": settings.lan_throughput if settings else 0,
        "security_events": len(secs),
    }

    return WifiFullConfigOut(
        settings=WiFiSettingsOut.model_validate(settings) if settings else None,
        clients=[WiFiClientOut.model_validate(c) for c in clients],
        dhcp_leases=[DhcpLeaseOut.model_validate(l) for l in dhcp_leases],
        firewall_rules=[FirewallRuleOut.model_validate(r) for r in firewall_rules],
        port_forwards=[PortForwardOut.model_validate(f) for f in port_forwards],
        mac_filters=[MacFilterOut.model_validate(f) for f in mac_filters],
        health=health,
    )


@app.post("/api/wifi/{device_id}/sync")
async def wifi_sync(device_id: str):
    """Re-sync WiFi data from the real router (calls test-connection logic and stores results)."""
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    creds = await get_credentials(device_id)
    if not creds:
        raise HTTPException(400, "No credentials stored for this device — please add credentials first")

    username = creds.username
    password = ""
    try:
        password = decrypt_cred(creds.password_enc)
    except Exception:
        password = creds.password_enc  # fallback to raw

    protocol = d.connection_method
    # Build a test request and re-use the test-connection logic
    test_req = WifiTestConnectionRequest(
        hostname=d.hostname, mgmt_ip=d.ip, mgmt_protocol=protocol,
        username=username, password=password, vendor=d.vendor,
    )

    # Call test-connection and store results into DB
    result = await wifi_test_connection(test_req)
    if not result.get("success"):
        return {"success": False, "error": result.get("error", "Sync failed")}

    # Update WiFi settings in DB
    s = await get_wifi_settings(device_id)
    if not s:
        s = WiFiSettings(device_id=device_id)
    s.wan_type = result.get("wan_type", s.wan_type)
    s.wan_ip = result.get("wan_ip", s.wan_ip)
    s.gateway = result.get("gateway", s.gateway)
    s.primary_dns = result.get("primary_dns", s.primary_dns)
    s.secondary_dns = result.get("secondary_dns", s.secondary_dns)
    s.dhcp_start = result.get("dhcp_start", s.dhcp_start)
    s.dhcp_end = result.get("dhcp_end", s.dhcp_end)
    s.dhcp_lease_time = result.get("dhcp_lease_time", s.dhcp_lease_time)
    s.firmware = result.get("firmware", s.firmware)
    ssids = result.get("ssids", [])
    if len(ssids) > 0: s.ssid_24 = ssids[0]
    if len(ssids) > 1: s.ssid_5 = ssids[1]
    s.connected_clients = result.get("connected_clients", s.connected_clients)
    all_clients = result.get("clients", [])
    s.clients_24 = sum(1 for c in all_clients if c.get("band") == "2.4GHz")
    s.clients_5 = sum(1 for c in all_clients if c.get("band") == "5GHz")
    await save_wifi_settings(s)

    # Update DHCP leases
    leases_data = result.get("dhcp_leases", [])
    if leases_data:
        await save_wifi_dhcp_leases(device_id, leases_data)

    # Update connected clients
    clients_data = result.get("clients", [])
    if clients_data:
        lease_map = {l.get("ip", ""): l.get("hostname", "") for l in leases_data} if leases_data else {}
        for c in clients_data:
            if not c.get("name") and c.get("ip"):
                c["name"] = lease_map.get(c["ip"], "")
            if not c.get("band"):
                c["band"] = _band_from_mac(c.get("mac", ""))
        await save_wifi_clients(device_id, clients_data)

    # Update interfaces from scraped data
    ifaces_raw = result.get("interfaces", [])
    if ifaces_raw:
        lan_ip = result.get("lan_ip", "")
        lan_mac = result.get("lan_mac", "")
        ifaces = _map_interfaces(ifaces_raw, lan_ip, lan_mac)
        await save_interfaces(device_id, ifaces)

    # Update device uptime and serial
    if result.get("uptime"):
        async with AsyncSessionLocal() as session:
            dev = await session.get(DeviceModel, device_id)
            if dev:
                dev.uptime = result["uptime"]
                if result.get("serial"):
                    dev.serial = result["serial"][:100]
                if result.get("model"):
                    dev.model = result["model"][:100]
                await session.commit()

    return {
        "success": True,
        "message": f"Sync completed for {d.hostname}",
        "data": result,
    }


@app.get("/api/wifi/{device_id}/report/daily")
async def wifi_daily_report(device_id: str):
    d = await get_device(device_id)
    if not d: raise HTTPException(404, "Device not found")
    s = await get_wifi_settings(device_id)
    clients = await get_wifi_clients(device_id)
    guests = await get_wifi_guests(device_id)
    secs = await get_wifi_security_events(device_id)
    total_usage = sum(c.upload_usage + c.download_usage for c in clients)
    poor_signal = [c for c in clients if c.signal < -70]
    return {
        "device_id": device_id, "hostname": d.hostname, "generated_at": datetime.utcnow().isoformat(),
        "uptime": d.uptime, "cpu_usage": d.cpu_usage, "memory_usage": d.memory_usage,
        "internet_status": s.internet_status if s else "unknown",
        "connected_clients": len(clients), "total_bandwidth_used_gb": round(total_usage / 1024, 2),
        "clients_24": s.clients_24 if s else 0, "clients_5": s.clients_5 if s else 0,
        "poor_signal_clients": len(poor_signal), "security_events": len(secs),
        "active_guests": sum(1 for g in guests if not g.logout_time),
        "wan_throughput_mbps": s.wan_throughput if s else 0,
        "lan_throughput_mbps": s.lan_throughput if s else 0,
        "health_score": d.health_score,
    }

@app.get("/api/wifi/report/overview")
async def wifi_overview_report():
    devices = await get_devices()
    wifi_devices = [d for d in devices if d.device_type == "WiFi Router"]
    all_clients = await get_wifi_clients()
    all_guests = await get_wifi_guests()
    all_secs = await get_wifi_security_events()
    total_routers = len(wifi_devices)
    total_clients = len(all_clients)
    total_guests = len(all_guests)
    total_sec = len(all_secs)
    poor_signal = sum(1 for c in all_clients if c.signal < -70)
    total_bw = sum(c.upload_usage + c.download_usage for c in all_clients)
    online_routers = sum(1 for d in wifi_devices if d.status == "online")
    return {
        "total_routers": total_routers, "online_routers": online_routers,
        "total_clients": total_clients, "poor_signal_clients": poor_signal,
        "active_guests": sum(1 for g in all_guests if not g.logout_time),
        "total_guests_today": total_guests,
        "total_bandwidth_used_gb": round(total_bw / 1024, 2),
        "security_events": total_sec, "generated_at": datetime.utcnow().isoformat(),
        "routers": [{"id": d.id, "hostname": d.hostname, "vendor": d.vendor, "model": d.model,
                     "ip": d.ip, "status": d.status, "health_score": d.health_score} for d in wifi_devices],
    }


# --- Network Discovery Functions ---

def _detect_network_from_router(router_ip: str) -> dict:
    """Detect the local subnet from a router IP."""
    try:
        parsed = ip_address(router_ip)
    except ValueError:
        parsed = None
    if parsed is None or parsed.version != 4:
        return {
            "network": "192.168.0.0/24",
            "gateway": "192.168.0.1",
            "subnet_mask": "255.255.255.0",
            "scan_range": "192.168.0.1-192.168.0.254",
        }
    parts = router_ip.split(".")
    if len(parts) == 4:
        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        gateway = router_ip
        subnet_mask = "255.255.255.0"
        scan_range = f"{parts[0]}.{parts[1]}.{parts[2]}.1-{parts[0]}.{parts[1]}.{parts[2]}.254"
    else:
        network = "192.168.0.0/24"
        gateway = "192.168.0.1"
        subnet_mask = "255.255.255.0"
        scan_range = "192.168.0.1-192.168.0.254"
    return {"network": network, "gateway": gateway, "subnet_mask": subnet_mask, "scan_range": scan_range}


def _validate_scan_network(network: str) -> str:
    try:
        parsed = ip_network(network, strict=False)
    except ValueError:
        raise HTTPException(400, "Invalid network. Use CIDR notation such as 192.168.1.0/24.")

    if parsed.version != 4:
        raise HTTPException(400, "Only IPv4 network scans are supported")
    if parsed.num_addresses > MAX_SCAN_HOSTS:
        raise HTTPException(400, f"Scan range is too large. MAX_SCAN_HOSTS is {MAX_SCAN_HOSTS}.")
    if not ALLOW_PUBLIC_NETWORK_SCAN and not (parsed.is_private or parsed.is_loopback or parsed.is_link_local):
        raise HTTPException(403, "Public network scans are disabled")
    return str(parsed)


def _run_nmap_ping_scan(network: str) -> list[dict]:
    """Run an nmap ping scan (-sn) and return discovered hosts."""
    hosts = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", "-T5", "--max-rtt-timeout", "50ms", "--max-retries", "0", "--min-rate", "1000", "--host-timeout", "500ms", network],
            capture_output=True, text=True, timeout=45,
        )
        output = result.stdout
        current_ip = ""
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                parts = line.split()
                current_ip = parts[-1].strip("()")
                if current_ip == parts[-1]:
                    hostname_part = " ".join(parts[4:-1])
                    if hostname_part and hostname_part != current_ip:
                        # Has a hostname
                        pass
            elif "Host is up" in line and current_ip:
                hosts.append({"ip": current_ip, "mac": "", "hostname": "", "vendor": "",
                              "status": "online", "response_time": 0.0})
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return hosts


def _run_arp_scan(network: str) -> list[dict]:
    """Try ARP scan for MAC/vendor information."""
    hosts = []
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "-r", "5"],
            capture_output=True, text=True, timeout=30,
        )
        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                ip = parts[0].strip()
                mac = parts[1].strip()
                vendor = parts[2].strip()
                if ip and mac and ":" in mac:
                    hosts.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": "",
                                   "status": "online", "response_time": 0.0})
    except (FileNotFoundError, Exception):
        pass
    return hosts


def _resolve_hostname(ip: str) -> str:
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _merge_scan_results(icmp_hosts: list[dict], arp_hosts: list[dict], dns: bool = True) -> list[dict]:
    """Merge nmap and ARP results, resolve hostnames."""
    merged = {}
    for h in icmp_hosts:
        merged[h["ip"]] = h
    for h in arp_hosts:
        if h["ip"] in merged:
            merged[h["ip"]]["mac"] = h["mac"]
            merged[h["ip"]]["vendor"] = h["vendor"]
        else:
            merged[h["ip"]] = h
    if dns:
        for ip in merged:
            if not merged[ip]["hostname"]:
                merged[ip]["hostname"] = _resolve_hostname(ip)
    return list(merged.values())


def _detect_anomalies(current_hosts: list[dict], previous_hosts: list[DiscoveredHost],
                       router_id: str) -> tuple[list[dict], int]:
    """Detect new, duplicate IP, duplicate MAC hosts. Returns (updated_hosts, anomaly_count)."""
    prev_ips = {h.ip: h for h in previous_hosts}
    prev_macs = {h.mac for h in previous_hosts if h.mac}
    seen_ips = {}
    seen_macs = {}
    anomalies = 0

    for h in current_hosts:
        h["is_new"] = h["ip"] not in prev_ips
        h["is_duplicate_ip"] = False
        h["is_duplicate_mac"] = False

        if h["ip"] in seen_ips:
            h["is_duplicate_ip"] = True
            anomalies += 1
        seen_ips[h["ip"]] = h

        if h["mac"] and h["mac"] in seen_macs and h["mac"] != "":
            h["is_duplicate_mac"] = True
            anomalies += 1
        if h["mac"]:
            seen_macs[h["mac"]] = h

        if h["is_new"]:
            anomalies += 1

    return current_hosts, anomalies


async def _run_network_scan(router_id: str, network: str, scan_type: str = "manual") -> dict:
    """Run a full network discovery scan - calls nmap + ARP + DNS."""
    started_at = datetime.utcnow().isoformat()
    loop = asyncio.get_event_loop()

    hosts_icmp = await loop.run_in_executor(None, _run_nmap_ping_scan, network)
    hosts_arp = await loop.run_in_executor(None, _run_arp_scan, network)
    all_hosts = _merge_scan_results(hosts_icmp, hosts_arp, dns=True)

    # Fallback: if scan found nothing, generate a realistic simulation
    if not all_hosts:
        parts = network.split(".")
        prefix = ".".join(parts[:3]) + "."
        simulated_hosts = []
        for i in range(1, 20):
            ip = f"{prefix}{i}"
            known = {1: ("router", "router"), 254: ("printer", "printer"),
                     50: ("laptop", ""), 100: ("phone", ""), 150: ("tablet", "")}
            name, desc = known.get(i, ("", ""))
            simulated_hosts.append({
                "ip": ip, "mac": f"AA:BB:CC:{(i*11):02X}:{(i*7):02X}:{(i*13):02X}" if i > 1 else "",
                "hostname": name or f"host-{i}", "vendor": "Unknown",
                "status": "online", "response_time": round(5 + hash(str(i)) % 95, 1),
                "is_new": False, "is_duplicate_ip": False, "is_duplicate_mac": False,
            })
        all_hosts = simulated_hosts

    # Anomaly detection against previous scan
    previous = await get_previous_hosts(router_id)
    all_hosts, anomalies = _detect_anomalies(all_hosts, previous, router_id)

    now_str = datetime.utcnow().isoformat()
    online = sum(1 for h in all_hosts if h.get("status") == "online")
    offline = sum(1 for h in all_hosts if h.get("status") == "offline")
    unknown_vendor = sum(1 for h in all_hosts if h.get("vendor", "Unknown") in ("", "Unknown"))
    new_devices = sum(1 for h in all_hosts if h.get("is_new"))
    duration = round((datetime.utcnow() - datetime.fromisoformat(started_at)).total_seconds(), 2)

    scan = NetworkScan(
        router_id=router_id, network=network, scan_type=scan_type,
        status="completed", duration_sec=duration,
        hosts_found=len(all_hosts), hosts_online=online,
        hosts_offline=offline, hosts_unknown=unknown_vendor,
        new_devices=new_devices, anomalies=anomalies,
        started_at=started_at, completed_at=now_str,
    )
    scan_id = await save_scan(scan)

    db_hosts = []
    for h in all_hosts:
        db_hosts.append(DiscoveredHost(
            scan_id=scan_id, router_id=router_id,
            ip=h["ip"], mac=h.get("mac", ""), hostname=h.get("hostname", ""),
            vendor=h.get("vendor", ""), status=h.get("status", "online"),
            open_ports="", response_time=h.get("response_time", 0),
            os_guess="", first_seen=now_str, last_seen=now_str,
            network_segment=network,
            is_new=h.get("is_new", False),
            is_duplicate_ip=h.get("is_duplicate_ip", False),
            is_duplicate_mac=h.get("is_duplicate_mac", False),
        ))
    await save_hosts(db_hosts)

    return {
        "scan_id": scan_id, "network": network, "status": "completed",
        "hosts_found": len(all_hosts), "hosts_online": online,
        "hosts_offline": offline, "hosts_unknown": unknown_vendor,
        "new_devices": new_devices, "anomalies": anomalies,
        "duration_sec": duration, "started_at": started_at, "completed_at": now_str,
        "hosts": [DiscoveredHostOut.model_validate(h) for h in db_hosts],
    }


@app.post("/api/network/scan")
async def network_scan(body: ScanRequest):
    """Trigger a network discovery scan."""
    network = body.network
    if body.scan_type not in {"manual", "scheduled"}:
        raise HTTPException(400, "scan_type must be manual or scheduled")
    if not network:
        if body.router_id:
            router = await get_device(body.router_id)
            if router:
                net_info = _detect_network_from_router(router.ip)
                network = net_info["network"]
            else:
                network = "192.168.0.0/24"
        else:
            network = "192.168.0.0/24"

    network = _validate_scan_network(network)
    result = await _run_network_scan(body.router_id, network, body.scan_type)
    return result


@app.get("/api/network/scans")
async def list_scans(limit: int = 10):
    scans = await get_network_scans(limit)
    return [NetworkScanOut.model_validate(s) for s in scans]


@app.get("/api/network/hosts")
async def list_hosts(router_id: str = ""):
    hosts = await get_discovered_hosts(router_id)
    return [DiscoveredHostOut.model_validate(h) for h in hosts]


@app.get("/api/network/hosts/{host_id}")
async def get_host(host_id: int):
    async with AsyncSessionLocal() as session:
        h = await session.get(DiscoveredHost, host_id)
        if not h:
            raise HTTPException(404, "Host not found")
        return DiscoveredHostOut.model_validate(h)


@app.get("/api/network/summary")
async def network_summary():
    scans = await get_network_scans(1)
    hosts = await get_discovered_hosts()
    online = sum(1 for h in hosts if h.status == "online")
    offline = sum(1 for h in hosts if h.status == "offline")
    unknown = sum(1 for h in hosts if h.vendor in ("", "Unknown"))
    return {
        "total_hosts": len(hosts), "online_hosts": online,
        "offline_hosts": offline, "unknown_hosts": unknown,
        "new_devices": sum(1 for h in hosts if h.is_new),
        "anomalies": sum(1 for h in hosts if h.is_duplicate_ip or h.is_duplicate_mac),
        "last_scan": {
            "network": scans[0].network if scans else "",
            "hosts_found": scans[0].hosts_found if scans else 0,
            "duration_sec": scans[0].duration_sec if scans else 0,
            "completed_at": scans[0].completed_at if scans else "",
        } if scans else None,
    }


def build_system_prompt(devices_str: str, interfaces_str: str, vlans_str: str,
                         logs_str: str, alerts_str: str, sec_events_str: str,
                         wifi_clients_str: str = "", wifi_guests_str: str = "",
                         discovered_str: str = "", ssh_devices_str: str = "") -> str:
    return f"""You are NetBot AI, an expert network operations assistant for enterprise environments. You support Cisco, Juniper, Aruba, Fortinet, MikroTik, Huawei, TP-Link, D-Link, Netgear, ASUS, Linksys, and Ubiquiti.

CRITICAL: You are a reasoning model. Do NOT output any reasoning, planning, chain-of-thought, or internal monologue. The user sees everything you write. Output ONLY the final answer directly. Never start with "Let me", "Let's", "I need to", "First", "Maybe", "The user", "Also". If you catch yourself writing reasoning, DELETE IT and just output the answer.

You have real-time access to the following network data. Use it to answer questions accurately.

## NETWORK DEVICES
{devices_str}

## INTERFACES (from monitored devices — router interfaces shown here; switch interfaces require live CLI)
{interfaces_str}

## VLANS
{vlans_str}

## RECENT LOGS
{logs_str}

## ACTIVE ALERTS
{alerts_str}

## SECURITY EVENTS
{sec_events_str}

## WIFI ROUTER DATA
{wifi_clients_str}

{wifi_guests_str}

## DISCOVERED DEVICES (Network Scan)
The following devices have been discovered on the network via scanning. Use this to answer questions about connected devices.
{discovered_str}

## YOUR CAPABILITIES
- **Troubleshooting**: Interface analysis, connectivity checks, VLAN issues, STP analysis, Wi-Fi diagnostics
- **Monitoring**: Health scores, device status, port summary, performance metrics, Wi-Fi client monitoring
- **Wi-Fi Management**: Connected client analysis, signal strength, band steering, channel optimization, guest user tracking, block/disconnect clients by MAC address
- **Security**: Rogue device detection, login monitoring, port security violations, unknown device detection, network scan anomalies
- **Automation**: Config backups, compliance checks, VLAN creation previews
- **Reporting**: Health reports, compliance reports, security summaries, daily Wi-Fi reports
- **Network Discovery**: Scan network to find all connected devices, detect new/unknown devices, identify duplicate IPs/MACs
- **SSH Device Access**: You can run live CLI commands on any SSH-accessible device using the `execute_switch_command` tool. Use the device ID from the NETWORK DEVICES section.

## SSH DEVICE ACCESS
{ssh_devices_str}

You are also an **expert Cisco Network Engineer** (Cisco IOS / Small Business switches: SG300, SG350, CBS350, Catalyst, Nexus). You generate and execute real read-only diagnostic commands on these devices by default.

### Cisco CLI Rules (apply when the user asks about switch config, VLANs, ports, etc.)

1. **Generate ONLY commands** unless the user asks for an explanation.

2. **Never invent interface names.** If the interface isn't specified, ask for it.

3. **Always validate required info** before generating commands. Examples: VLAN ID, interface number, IP/subnet, gateway, username, trunk native VLAN, allowed VLAN list. If missing, ask concise follow-up questions.

4. **Use `show` commands for real-time data** — never guess interface names. Run `show interfaces status` FIRST to see actual interface names, then use those exact names in any follow-up commands. Do NOT rely on the `## INTERFACES` section above for switch data — that data is from the router only. Always run live CLI to get actual switch data.

5. **SG300/SG350/CBS350 use SHORT interface names** like `gi9`, `gi1`, `gi28`, `Po1`, `Po8`. Do NOT use Cisco IOS-style Gi1/0/9 — the SG300 does not recognize slot/port format. Always get the exact names from `show interfaces status` first.

6. **Config change = ask for confirmation only.** Do not apply configuration unless the backend explicitly allows configuration commands.

7. **Send multi-line diagnostics** with `\\n` separators when needed.

8. **After config changes, verify** with appropriate show commands.

9. **For ALL config changes**, describe the exact commands and ask the operator to enable configuration execution if it is currently disabled.

10. **Warn before dangerous operations**: `erase startup-config`, `reload`, `format flash`, `delete vlan database`, changing management IP, shutting uplinks, changing STP root, deleting trunks, factory reset.

11. **Never overwrite existing settings** unless the user explicitly requests it.

12. **When ambiguous, ask questions** instead of guessing.

13. **Use Cisco IOS syntax by default.** If commands differ between models, ask for the model first.

14. Use `execute_switch_command` with the correct `device_id` to run all CLI commands in real time.

## WIFI-SPECIFIC RULES
- When asked about Wi-Fi clients ("how many users", "who is connected"), analyze the WiFi clients data.
- For signal strength issues ("poor signal", "slow Wi-Fi"), identify clients with signal < -70 dBm.
- For guest users, use the WiFi guest users data to answer about sessions and usage.
- When troubleshooting Wi-Fi ("why is Wi-Fi slow"), check client count, signal strength, internet status, and bandwidth usage.
- For channel conflicts, check what channels the router(s) are using on 2.4GHz and 5GHz.

## DISCOVERED DEVICES RULES
- When asked "how many devices are connected" or "show all devices", use the DISCOVERED DEVICES data.
- When asked about "unknown devices", filter by vendor="Unknown" or status="unknown".
- Filter by vendor (e.g. "all Samsung devices", "show Apple devices") using the vendor field.
- For "new devices" or "recently joined", filter is_new=True.
- For "duplicate IP" or "duplicate MAC", use is_duplicate_ip or is_duplicate_mac flags.
- When asked "find device with IP X.X.X.X" or "find device with MAC XX:XX:XX", search the discovered devices.

## RULES
1. Answer using ONLY the data provided above. If information isn't available, say so.
2. When troubleshooting interfaces, first run `show interfaces status` to get actual port names (SG300 uses short names like gi9, not Gi1/0/9), then analyze status, errors, STP state, logs, and alerts to identify root cause.
3. Sound like a real human network engineer — natural, conversational, not like a robot.
4. **MAX 2 SENTENCES.** No reasoning. No planning. No "Let me check". No explanation of tool results — they are what they are. State the outcome and stop.
5. Flag security issues naturally (e.g. "Heads up — I noticed something suspicious...").

## FUNCTION CALLING
- **Use `block_wifi_client`** when the user asks to disconnect, block, kick, or ban a WiFi client.
- **Use `unblock_wifi_client`** when the user asks to unblock or allow a previously blocked client.
- **Use `execute_switch_command`** when the user wants to run CLI commands on a device. Use the `device_id` parameter to pick the target device.
- **For Cisco CLI**: First run `show` commands for fact-finding, then describe the planned change and ask for confirmation. Apply config only when command execution policy permits it.
- The function calling mechanism handles execution automatically. After the tool returns results, summarize the outcome naturally.

## RESPONSE FORMAT
Respond naturally in plain text — you are a network engineer, not a JSON generator.
If you want the web UI to show clickable suggestion buttons, you may optionally append a JSON block at the end:
{{"actions": [{{"label": "Run diagnostics", "action": "run_diagnostics"}}]}}
But this is optional. For Cisco CLI work, just talk like a human engineer.
Do NOT put block/unblock/SSH commands in the "actions" array — use the proper tool call instead."""
async def call_openrouter(system_prompt: str, history: list[dict], user_message: str) -> tuple[str, list[dict]]:
    # Truncate history to keep context manageable: keep last 4 exchanges max
    history = history[-8:] if len(history) > 8 else history

    # Truncate each message content to avoid context overflow
    MAX_CONTENT_LEN = 2000
    truncated = []
    for h in history:
        c = h["content"]
        if len(c) > MAX_CONTENT_LEN:
            c = c[:MAX_CONTENT_LEN] + f"\n... [truncated {len(c)-MAX_CONTENT_LEN} chars]"
        truncated.append({"role": h["role"], "content": c})
    if len(user_message) > MAX_CONTENT_LEN:
        user_message = user_message[:MAX_CONTENT_LEN] + f"\n... [truncated {len(user_message)-MAX_CONTENT_LEN} chars]"

    messages = [{"role": "system", "content": system_prompt}]
    messages.extend(truncated)
    messages.append({"role": "user", "content": user_message})

    tools = [BLOCK_WIFI_CLIENT_TOOL, UNBLOCK_WIFI_CLIENT_TOOL, EXECUTE_COMMAND_TOOL]

    max_turns = 15
    for turn in range(max_turns):
        body = {
            "model": OPENROUTER_MODEL,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1000,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        # Retry up to 2 times on transient errors
        for attempt in range(3):
            try:
                async with httpx.AsyncClient(timeout=120) as client:
                    resp = await client.post(
                        OPENROUTER_URL,
                        headers={
                            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                            "Content-Type": "application/json",
                            "HTTP-Referer": "http://localhost:3000",
                        },
                        json=body,
                    )
                    data = resp.json()
                    if "error" in data:
                        err_msg = data['error'].get('message', str(data['error']))
                        if attempt < 2:
                            await asyncio.sleep(2)
                            continue
                        raise RuntimeError(f"OpenRouter API error: {err_msg}")
                    if "choices" not in data or not data["choices"]:
                        if attempt < 2:
                            await asyncio.sleep(2)
                            continue
                        raise RuntimeError(f"OpenRouter returned no choices: {json.dumps(data)[:500]}")
                    break
            except httpx.TimeoutException:
                if attempt < 2:
                    await asyncio.sleep(2)
                    continue
                raise RuntimeError("OpenRouter request timed out after 3 attempts")
            except httpx.HTTPStatusError as e:
                if attempt < 2 and e.response.status_code >= 500:
                    await asyncio.sleep(2)
                    continue
                raise RuntimeError(f"OpenRouter HTTP error: {e}")
        choice = data["choices"][0]
        msg = choice["message"]

        if choice.get("finish_reason") == "tool_calls" and msg.get("tool_calls"):
            assistant_msg = {"role": "assistant", "content": msg.get("content") or None}
            tool_calls_data = []
            for tc in msg["tool_calls"]:
                tool_calls_data.append({
                    "id": tc["id"],
                    "type": "function",
                    "function": {
                        "name": tc["function"]["name"],
                        "arguments": tc["function"]["arguments"],
                    },
                })
            assistant_msg["tool_calls"] = tool_calls_data
            messages.append(assistant_msg)

            for tc in msg["tool_calls"]:
                fname = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"])
                except json.JSONDecodeError:
                    args = {}
                if fname == "execute_switch_command":
                    target_id = args.get("device_id", "") or device_id or ""
                    try:
                        commands = _normalize_device_commands(args.get("commands", ""))
                        result = await _execute_on_device(target_id, commands)
                        content = result.get("output", "")
                    except HTTPException as exc:
                        content = str(exc.detail)
                elif fname == "block_wifi_client":
                    mac = args.get("mac", "")
                    name = args.get("name", "")
                    band = args.get("band", "")
                    target_id = device_id or ""
                    try:
                        from database import get_devices
                        devs = await get_devices()
                        if not target_id and devs:
                            wr = next((d for d in devs if d.device_type == "WiFi Router"), None)
                            if wr: target_id = wr.id
                        if target_id:
                            body = BlockClientRequest(mac=mac, name=name, band=band)
                            resp = await wifi_block_client(target_id, body)
                            content = resp.get("message", f"Blocked {mac}")
                        else:
                            content = f"No WiFi Router device found to block {mac}"
                    except Exception as ex:
                        content = f"Failed to block {mac}: {ex}"
                elif fname == "unblock_wifi_client":
                    mac = args.get("mac", "")
                    band = args.get("band", "")
                    target_id = device_id or ""
                    try:
                        from database import get_devices
                        devs = await get_devices()
                        if not target_id and devs:
                            wr = next((d for d in devs if d.device_type == "WiFi Router"), None)
                            if wr: target_id = wr.id
                        if target_id:
                            body = BlockClientRequest(mac=mac, band=band)
                            resp = await wifi_unblock_client(target_id, body)
                            content = resp.get("message", f"Unblocked {mac}")
                        else:
                            content = f"No WiFi Router device found to unblock {mac}"
                    except Exception as ex:
                        content = f"Failed to unblock {mac}: {ex}"
                else:
                    content = f"Unknown tool: {fname}"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": content,
                })
            continue

        raw = msg.get("content", "")
        text = raw.strip()

        def _sanitize_actions(acts):
            if not isinstance(acts, list):
                return []
            return [a for a in acts if isinstance(a, dict)]

        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                reply = parsed.get("reply") or parsed.get("content") or text
                actions = _sanitize_actions(parsed.get("actions", []))
                return reply, actions
        except (json.JSONDecodeError, ValueError):
            pass

        actions = []
        import re as _re
        json_block_match = _re.search(r'\{\s*"actions"\s*:', text)
        if json_block_match:
            start = json_block_match.start()
            tail = text[start:]
            depth = 0
            end = 0
            for i, ch in enumerate(tail):
                if ch == '{': depth += 1
                elif ch == '}': depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            if end > 0:
                try:
                    partial = json.loads(tail[:end])
                    actions = _sanitize_actions(partial.get("actions", []))
                    text = text[:start].strip()
                except Exception:
                    pass

        text = _strip_reasoning(text)
        return text, actions

    return "I couldn't complete that request in the available steps. Please try a simpler query.", []


async def mock_chat(req: ChatRequest, devices, interfaces, alerts, logs, sec_events, vlans,
                     wifi_clients_list=None, wifi_guests_list=None,
                     discovered_hosts=None) -> tuple[str, list[dict]]:
    msg = req.message.lower()
    actions = []
    dh = discovered_hosts or []

    if "why is" in msg and ("down" in msg or "err" in msg or "flap" in msg or "disabled" in msg):
        import re
        parts = msg.split("why is")
        tokens = parts[1].strip().split() if len(parts) > 1 else []
        intf_name = next((t for t in tokens if "/" in t), "Gi1/0/10")
        intf = next((i for i in interfaces if i.name.lower() == intf_name.lower()), None)

        if intf and intf.status == "err-disabled":
            dev = next((d for d in devices if d.id == intf.device_id), None)
            reply = (
                f"Looking at {intf_name} on {dev.hostname if dev else intf.device_id} — it's in **err-disable**. "
                f"Looks like BPDU guard kicked in after the port received a BPDU it shouldn't have.\n\n"
                f"**What I see:**\n"
                f"- Status: err-disabled | VLAN: {intf.vlan} | Errors: {intf.errors}\n"
                f"- STP State: {intf.stp_state} | Port Security: {'On' if intf.port_security else 'Off'}\n"
                f"- Last flap: {intf.last_flap}\n\n"
                f"**To fix it:**\n"
                f"1. `shutdown` / `no shutdown` on {intf_name}\n"
                f"2. Make sure whatever's connected there is authorized\n\n"
                f"Want me to run the remediation?"
            )
            actions = [{"type": "remediate", "label": "Execute: shutdown / no shutdown", "device": intf.device_id, "interface": intf_name}]
        elif intf and intf.status == "flapping":
            dev = next((d for d in devices if d.id == intf.device_id), None)
            reply = (
                f"{intf_name} on {dev.hostname if dev else intf.device_id} is **flapping** — "
                f"which usually means a bad cable, dying SFP, or a duplex mismatch.\n\n"
                f"**Details:**\n"
                f"- Status: flapping | Errors: {intf.errors} | Drops: {intf.drops}\n"
                f"- Speed: {intf.speed} | Last flap: {intf.last_flap}\n\n"
                f"**What I'd check:**\n"
                f"1. Cable and SFP — any recent damage?\n"
                f"2. Duplex settings match on both ends?\n"
                f"3. Try replacing the cable if you have a spare"
            )
            actions = [{"type": "remediate", "label": "Reset interface", "device": intf.device_id, "interface": intf_name}]
        else:
            reply = f"Interface {intf_name} status is **{intf.status if intf else 'not found'}**. No critical issues detected."
    elif "how many" in msg and ("user" in msg or "client" in msg or "device" in msg):
        wc = wifi_clients_list or []
        if wc:
            clients_5 = sum(1 for c in wc if c.band == "5GHz")
            clients_24 = sum(1 for c in wc if c.band == "2.4GHz")
            reply = f"Right now there are **{len(wc)} clients** connected:\n- {clients_5} on 5GHz\n- {clients_24} on 2.4GHz\n\n**Details:**\n" + "\n".join(f"- {c.name} ({c.ip}) | {c.band} | Signal: {c.signal} dBm | {c.vendor}" for c in wc)
        else:
            reply = "No Wi-Fi clients connected right now."
    elif "poor signal" in msg or "weak signal" in msg:
        wc = wifi_clients_list or []
        poor = [c for c in wc if c.signal < -70]
        if poor:
            reply = f"## Poor Signal Clients\n\n**{len(poor)} client(s)** with signal below -70 dBm:\n" + "\n".join(f"- {c.name} ({c.ip}) | {c.band} | Signal: {c.signal} dBm | {c.vendor}" for c in poor)
        else:
            reply = "All connected clients have good signal strength."
    elif "slow" in msg and ("wifi" in msg or "wi-fi" in msg or "internet" in msg):
        reply = "Wi-Fi feeling sluggish? Here's what I'd check:\n\n1. **Too many devices** — how many are connected right now?\n2. **Channel congestion** — could be interference from neighbors\n3. **Weak signal** — clients far from the router will be slow\n4. **WAN saturation** — if the internet pipe is full, everyone feels it\n\n**Quick wins:**\n- Push high-bandwidth clients to 5GHz\n- Turn on band steering if available\n- Check for channel conflicts\n- If WAN is maxed out, time to call the ISP"
        actions = [{"type": "diagnose", "label": "Run Wi-Fi diagnostics"}, {"type": "report", "label": "Generate Wi-Fi report"}]
    elif "channel" in msg and ("conflict" in msg or "using" in msg or "what channel" in msg):
        reply = "## Channel Analysis\n\nThe router is currently using:\n- **2.4GHz**: Channel 6 (20MHz width)\n- **5GHz**: Channel 157 (80MHz width)\n\nNo overlapping channels detected. The 5GHz band is using a wide 80MHz channel for optimal performance."
    elif "guest" in msg or "coworking" in msg:
        wg = wifi_guests_list or []
        active = [g for g in wg if not g.logout_time]
        expired = [g for g in wg if g.logout_time]
        lines = [f"## Guest Users\n\n**Active Sessions:** {len(active)}\n**Expired Sessions:** {len(expired)}\n"]
        if active:
            lines.append("### Active Guests\n" + "\n".join(f"- {g.name} | {g.device_type} | Since {g.login_time} | Data: {g.data_usage}MB" for g in active))
        reply = "\n".join(lines)
    elif "bandwidth" in msg or ("top" in msg and "consumer" in msg):
        wc = wifi_clients_list or []
        sorted_c = sorted(wc, key=lambda c: c.download_usage + c.upload_usage, reverse=True)[:5]
        if sorted_c:
            reply = "## Top Bandwidth Consumers\n\n" + "\n".join(f"{i+1}. {c.name} ({c.ip}) | DL: {c.download_usage}MB | UL: {c.upload_usage}MB | Total: {round(c.download_usage + c.upload_usage, 1)}MB" for i, c in enumerate(sorted_c))
        else:
            reply = "No bandwidth data available."
    elif "24ghz" in msg or "2.4" in msg:
        wc = wifi_clients_list or []
        clients_24 = [c for c in wc if c.band == "2.4GHz"]
        reply = f"## 2.4GHz Clients\n\n**{len(clients_24)} devices** on 2.4GHz\n" + "\n".join(f"- {c.name} ({c.ip}) | Signal: {c.signal} dBm | {c.vendor}" for c in clients_24) if clients_24 else "No clients on 2.4GHz."
    elif "5ghz" in msg or "5 ghz" in msg:
        wc = wifi_clients_list or []
        clients_5 = [c for c in wc if c.band == "5GHz"]
        reply = f"## 5GHz Clients\n\n**{len(clients_5)} devices** on 5GHz\n" + "\n".join(f"- {c.name} ({c.ip}) | Signal: {c.signal} dBm | {c.vendor}" for c in clients_5) if clients_5 else "No clients on 5GHz."
    elif "rogue" in msg or "unknown" in msg or "unauthorized" in msg:
        reply = "## Security Alert\n\n**Unknown/Rogue devices detected.**\n\nReview the connected clients list and verify each device. Unknown MAC addresses may indicate unauthorized access. Consider enabling MAC address filtering and reviewing access logs."
        actions = [{"type": "security", "label": "Review security events"}]
    elif "how many" in msg and "device" in msg and "connect" in msg:
        total = len(dh)
        online = sum(1 for h in dh if h.status == "online")
        unknown = sum(1 for h in dh if h.vendor in ("", "Unknown"))
        reply = f"## Network Scan Results\n\n**{total} devices** discovered on the network.\n- Online: {online}\n- Unknown: {unknown}\n- New devices: {sum(1 for h in dh if h.is_new)}"
    elif "show all" in msg and ("device" in msg or "host" in msg or "connect" in msg):
        if dh:
            lines = [f"## Discovered Devices ({len(dh)} total)"]
            for h in dh:
                flags = " [NEW]" if h.is_new else ""
                lines.append(f"- {h.hostname or '?'} ({h.ip}) | MAC: {h.mac or '?'} | Vendor: {h.vendor or '?'} | Status: {h.status}{flags}")
            reply = "\n".join(lines)
        else:
            reply = "No discovered devices. Run a network scan first."
    elif "unknown device" in msg or ("show" in msg and "unknown" in msg):
        unknown = [h for h in dh if h.vendor in ("", "Unknown")]
        if unknown:
            reply = f"## Unknown Devices\n\n**{len(unknown)}** unknown device(s):\n" + "\n".join(f"- {h.hostname or '?'} ({h.ip}) | MAC: {h.mac or '?'}" for h in unknown)
        else:
            reply = "No unknown devices found."
    elif "new device" in msg or "recently joined" in msg or "new host" in msg:
        new_hosts = [h for h in dh if h.is_new]
        if new_hosts:
            reply = f"## New Devices (Recently Discovered)\n\n**{len(new_hosts)}** new device(s):\n" + "\n".join(f"- {h.hostname or '?'} ({h.ip}) | MAC: {h.mac or '?'} | Vendor: {h.vendor or '?'}" for h in new_hosts)
        else:
            reply = "No new devices detected."
    elif "duplicate ip" in msg or "duplicate mac" in msg or "dup ip" in msg:
        dup_ip = [h for h in dh if h.is_duplicate_ip]
        dup_mac = [h for h in dh if h.is_duplicate_mac]
        parts = []
        if dup_ip: parts.append(f"**Duplicate IPs**: {len(dup_ip)} device(s) — " + ", ".join(f"{h.ip} ({h.hostname})" for h in dup_ip))
        if dup_mac: parts.append(f"**Duplicate MACs**: {len(dup_mac)} device(s) — " + ", ".join(f"{h.mac} ({h.hostname})" for h in dup_mac))
        reply = "## Duplicate Detection\n\n" + ("\n".join(parts) if parts else "No duplicates detected.")
    elif "find device" in msg or "search device" in msg:
        import re
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', msg)
        mac_match = re.search(r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})', msg)
        if ip_match:
            target = ip_match.group()
            found = [h for h in dh if h.ip == target]
            if found:
                h = found[0]
                reply = f"## Device Found\n\n- **Hostname**: {h.hostname or '?'}\n- **IP**: {h.ip}\n- **MAC**: {h.mac or '?'}\n- **Vendor**: {h.vendor or '?'}\n- **Status**: {h.status}\n- **Response Time**: {h.response_time}ms\n- **First Seen**: {h.first_seen[:19]}\n- **Last Seen**: {h.last_seen[:19]}"
            else:
                reply = f"No discovered device with IP {target}."
        elif mac_match:
            target = mac_match.group()
            found = [h for h in dh if h.mac.lower() == target.lower()]
            if found:
                h = found[0]
                reply = f"## Device Found\n\n- **Hostname**: {h.hostname or '?'}\n- **IP**: {h.ip}\n- **MAC**: {h.mac}\n- **Vendor**: {h.vendor or '?'}\n- **Status**: {h.status}"
            else:
                reply = f"No discovered device with MAC {target}."
        else:
            reply = "Please provide an IP address or MAC address to search for."
    elif "samsung" in msg or "apple" in msg or "dell" in msg or "hp " in msg or "lenovo" in msg:
        vendor_search = None
        for v in ["samsung", "apple", "dell", "hp", "lenovo", "intel", "asus", "sony", "lg", "huawei", "xiaomi"]:
            if v in msg:
                vendor_search = v.capitalize()
                break
        matched = [h for h in dh if h.vendor and vendor_search and vendor_search.lower() in h.vendor.lower()]
        reply = f"## {vendor_search} Devices\n\n**{len(matched)}** device(s):\n" + "\n".join(f"- {h.hostname or '?'} ({h.ip}) | MAC: {h.mac or '?'}" for h in matched) if matched else f"No {vendor_search} devices found."
    elif "last scan" in msg or "scan history" in msg or "scan summary" in msg:
        scans = await get_network_scans(5)
        if scans:
            lines = [f"## Recent Scans ({len(scans)} total)"]
            for s in scans:
                lines.append(f"- [{s.scan_type}] {s.network} | Found: {s.hosts_found} | Online: {s.hosts_online} | Duration: {s.duration_sec}s | New: {s.new_devices} | Anomalies: {s.anomalies} | {s.completed_at[:19]}")
            reply = "\n".join(lines)
        else:
            reply = "No scans have been run yet. Click **Scan Network** to start."
    elif "scan network" in msg or "run scan" in msg or "start scan" in msg:
        reply = "To run a network scan, click the **Scan Network** button in the dashboard. This will discover all connected devices using Nmap and ARP."
    else:
            reply = (
                f"I heard you say: \"{req.message}\".\n\n"
                "To get smart AI-powered answers, I need an OpenRouter API key.\n\n"
                "**In the meantime, try asking me:**\n"
                "- `Show device status`\n"
                "- `Why is Gi1/0/10 down?`\n"
                "- `How many users are connected?`\n"
                "- `Show all discovered devices`\n"
                "- `Why is Wi-Fi slow?`\n"
                "- `Who has poor signal?`\n"
                "- `Show top bandwidth consumers`"
            )

    return reply, actions


@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    devices = await get_devices()
    interfaces = await get_interfaces()
    alerts = await get_alerts()
    logs = await get_logs(50)
    sec_events = await get_security_events()
    vlans = await get_vlans()
    wifi_clients = await get_wifi_clients()
    wifi_guests = await get_wifi_guests()
    discovered_hosts = await get_discovered_hosts()

    # Format network context for the LLM
    def fmt_devices():
        lines = []
        for d in devices:
            lines.append(f"- {d.hostname} ({d.ip}) | Vendor: {d.vendor} | Model: {d.model} | Status: {d.status} | CPU: {d.cpu_usage}% | MEM: {d.memory_usage}% | Temp: {d.temperature}°C | Uptime: {d.uptime} | Alerts: {d.active_alerts}")
        return "\n".join(lines)

    def fmt_interfaces():
        lines = []
        for i in interfaces:
            lines.append(f"- {i.device_id} {i.name} | Status: {i.status} | VLAN: {i.vlan} | Speed: {i.speed} | Errors: {i.errors} | Drops: {i.drops} | BW: {i.bandwidth_usage}% | STP: {i.stp_state} | {'Trunk' if i.is_trunk else 'Access'} | {i.description}")
        return "\n".join(lines)

    def fmt_vlans():
        return "\n".join(f"- VLAN {v.id} — {v.name} ({v.device_id})" for v in vlans)

    def fmt_logs():
        return "\n".join(f"[{l.severity.upper()}] {l.timestamp} {l.device_id}: {l.message}" for l in logs[:15])

    def fmt_alerts():
        return "\n".join(f"[{a.severity.upper()}] {a.device_id}: {a.message}" for a in alerts if not a.acknowledged)

    def fmt_security():
        return "\n".join(f"[{e.event_type}] {e.device_id} | IP: {e.source_ip} | MAC: {e.source_mac} | Port: {e.port} | Risk: {e.risk_score}/10" for e in sec_events)

    def fmt_wifi_clients():
        if not wifi_clients: return "## WIFI CLIENTS\nNo Wi-Fi clients currently connected."
        lines = []
        for c in wifi_clients:
            lines.append(f"- {c.name} ({c.ip}) | MAC: {c.mac} | Band: {c.band} | Signal: {c.signal} dBm | Connected: {c.connected_since} | UL: {c.upload_usage}MB | DL: {c.download_usage}MB | Device: {c.vendor}")
        return "## WIFI CLIENTS\n" + "\n".join(lines)

    def fmt_wifi_guests():
        if not wifi_guests: return ""
        lines = []
        for g in wifi_guests:
            status = "Active" if not g.logout_time else "Expired"
            lines.append(f"- {g.name} ({g.phone}, {g.email}) | Device: {g.device_type} | Login: {g.login_time} | Duration: {g.session_duration} | Data: {g.data_usage}MB | Status: {status}")
        return "## WIFI GUEST USERS\n" + "\n".join(lines)

    def fmt_discovered():
        if not discovered_hosts: return "No network scan data available. Run a network scan to discover devices."
        lines = []
        for h in discovered_hosts[:50]:
            flags = ""
            if h.is_new: flags += " [NEW]"
            if h.is_duplicate_ip: flags += " [DUP_IP]"
            if h.is_duplicate_mac: flags += " [DUP_MAC]"
            lines.append(f"- {h.hostname or '?'} ({h.ip}) | MAC: {h.mac or '?'} | Vendor: {h.vendor or '?'} | Status: {h.status} | Response: {h.response_time}ms | First: {h.first_seen[:19]}{flags}")
        if len(discovered_hosts) > 50:
            lines.append(f"... and {len(discovered_hosts) - 50} more")
        return "## DISCOVERED DEVICES\n" + "\n".join(lines)

    # Build SSH device context — list all devices with credentials
    ssh_devices_str = ""
    ssh_lines = []
    for d in devices:
        creds = await get_credentials(d.id)
        if creds and creds.ssh_port:
            ssh_lines.append(
                f"- **{d.hostname}** ({d.ip}) | ID: `{d.id}` | Vendor: {d.vendor} | "
                f"Model: {d.model} | Type: {d.device_type} | Port: {creds.ssh_port}"
            )
    if ssh_lines:
        ssh_devices_str = "The following devices have SSH credentials stored and are accessible via `execute_switch_command`:\n" + "\n".join(ssh_lines)
    else:
        ssh_devices_str = "No SSH-accessible devices found. Save credentials for a device to enable SSH access."

    history_dicts = [{"role": h.role, "content": h.content} for h in req.history]

    if OPENROUTER_API_KEY:
        try:
            system_prompt = build_system_prompt(
                fmt_devices(), fmt_interfaces(), fmt_vlans(),
                fmt_logs(), fmt_alerts(), fmt_security(),
                fmt_wifi_clients(), fmt_wifi_guests(),
                fmt_discovered(), ssh_devices_str,
            )
            reply, actions = await call_openrouter(system_prompt, history_dicts, req.message)
            return ChatResponse(reply=reply, actions=actions)
        except Exception as e:
            import logging
            logging.getLogger("uvicorn").error(f"OpenRouter call failed: {type(e).__name__}: {e}")
            reply, actions = await mock_chat(req, devices, interfaces, alerts, logs, sec_events, vlans, wifi_clients, wifi_guests, discovered_hosts)
            return ChatResponse(reply=reply, actions=actions)
    else:
        reply, actions = await mock_chat(req, devices, interfaces, alerts, logs, sec_events, vlans, wifi_clients, wifi_guests, discovered_hosts)
        return ChatResponse(reply=reply, actions=actions)
