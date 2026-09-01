import os
import json
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import select, String, Integer, Float, Boolean, Text, ForeignKey, JSON
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://netbot:netbot@localhost:5432/netbot")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
REQUIRE_ENCRYPTION_KEY = os.getenv("REQUIRE_ENCRYPTION_KEY", "").strip().lower() in {"1", "true", "yes", "on"}

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


# --- Encryption ---

def _derive_key(secret: str) -> bytes:
    if not secret:
        if REQUIRE_ENCRYPTION_KEY:
            raise RuntimeError("ENCRYPTION_KEY must be set when REQUIRE_ENCRYPTION_KEY=true")
        secret = "netbot-default-dev-key-change-in-production"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"netbot-salt", iterations=100000)
    return urlsafe_b64encode(kdf.derive(secret.encode()))

_cipher = Fernet(_derive_key(ENCRYPTION_KEY))

def encrypt_cred(value: str) -> str:
    return _cipher.encrypt(value.encode()).decode()

def decrypt_cred(token: str) -> str:
    return _cipher.decrypt(token.encode()).decode()


# --- Models ---

class Base(DeclarativeBase):
    pass


class DeviceModel(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(50), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(100))
    vendor: Mapped[str] = mapped_column(String(50), default="Cisco")
    model: Mapped[str] = mapped_column(String(100), default="")
    serial: Mapped[str] = mapped_column(String(100), default="")
    version: Mapped[str] = mapped_column(String(50), default="")
    category: Mapped[str] = mapped_column(String(50))
    device_type: Mapped[str] = mapped_column(String(50))
    ip: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="online")
    cpu_usage: Mapped[float] = mapped_column(Float, default=0)
    memory_usage: Mapped[float] = mapped_column(Float, default=0)
    temperature: Mapped[float] = mapped_column(Float, default=0)
    uptime: Mapped[str] = mapped_column(String(50), default="")
    last_seen: Mapped[str] = mapped_column(String(50), default="")
    interface_errors: Mapped[int] = mapped_column(Integer, default=0)
    active_alerts: Mapped[int] = mapped_column(Integer, default=0)
    location: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    connection_method: Mapped[str] = mapped_column(String(20), default="SSH")
    tags: Mapped[str] = mapped_column(Text, default="")  # comma-separated
    health_score: Mapped[int] = mapped_column(Integer, default=100)

    interfaces = relationship("InterfaceModel", back_populates="device", lazy="selectin")
    credentials = relationship("DeviceCredential", back_populates="device", uselist=False, lazy="selectin")
    discoveries = relationship("DiscoveryResult", back_populates="device", lazy="selectin")


class DeviceCredential(Base):
    __tablename__ = "device_credentials"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"), unique=True)
    username: Mapped[str] = mapped_column(String(100), default="")
    password_enc: Mapped[str] = mapped_column(Text, default="")
    enable_secret_enc: Mapped[str] = mapped_column(Text, default="")
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    auth_type: Mapped[str] = mapped_column(String(20), default="password")  # password, ssh_key
    ssh_key_enc: Mapped[str] = mapped_column(Text, default="")
    passphrase_enc: Mapped[str] = mapped_column(Text, default="")
    snmp_version: Mapped[str] = mapped_column(String(10), default="")
    snmp_community: Mapped[str] = mapped_column(String(100), default="")
    snmp_v3_username: Mapped[str] = mapped_column(String(100), default="")
    snmp_auth_protocol: Mapped[str] = mapped_column(String(10), default="")
    snmp_auth_password_enc: Mapped[str] = mapped_column(Text, default="")
    snmp_privacy_protocol: Mapped[str] = mapped_column(String(10), default="")
    snmp_privacy_password_enc: Mapped[str] = mapped_column(Text, default="")
    api_base_url: Mapped[str] = mapped_column(String(500), default="")
    api_token_enc: Mapped[str] = mapped_column(Text, default="")
    api_username: Mapped[str] = mapped_column(String(100), default="")
    api_password_enc: Mapped[str] = mapped_column(Text, default="")
    last_connected: Mapped[str] = mapped_column(String(50), default="")

    device = relationship("DeviceModel", back_populates="credentials")

    def to_secure_dict(self) -> dict:
        return {
            "username": self.username,
            "ssh_port": self.ssh_port,
            "auth_type": self.auth_type,
            "snmp_version": self.snmp_version,
            "snmp_community": "***" if self.snmp_community else "",
            "snmp_v3_username": self.snmp_v3_username,
            "api_base_url": self.api_base_url,
            "api_username": self.api_username,
            "last_connected": self.last_connected,
        }


class DiscoveryResult(Base):
    __tablename__ = "discovery_results"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    command: Mapped[str] = mapped_column(String(200))
    output: Mapped[str] = mapped_column(Text, default="")
    collected_at: Mapped[str] = mapped_column(String(50))

    device = relationship("DeviceModel", back_populates="discoveries")


class InterfaceModel(Base):
    __tablename__ = "interfaces"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="up")
    vlan: Mapped[str] = mapped_column(String(10), default="1")
    duplex: Mapped[str] = mapped_column(String(10), default="auto")
    speed: Mapped[str] = mapped_column(String(20), default="1G")
    mtu: Mapped[int] = mapped_column(Integer, default=1500)
    errors: Mapped[int] = mapped_column(Integer, default=0)
    drops: Mapped[int] = mapped_column(Integer, default=0)
    bandwidth_usage: Mapped[float] = mapped_column(Float, default=0)
    description: Mapped[str] = mapped_column(Text, default="")
    mac: Mapped[str] = mapped_column(String(50), default="")
    ip: Mapped[str] = mapped_column(String(50), default="")
    last_flap: Mapped[str] = mapped_column(String(50), default="")
    port_security: Mapped[bool] = mapped_column(Boolean, default=False)
    bpdu_guard: Mapped[bool] = mapped_column(Boolean, default=False)
    stp_state: Mapped[str] = mapped_column(String(20), default="forwarding")
    is_trunk: Mapped[bool] = mapped_column(Boolean, default=False)
    device = relationship("DeviceModel", back_populates="interfaces")


class VLANModel(Base):
    __tablename__ = "vlans"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    status: Mapped[str] = mapped_column(String(20), default="active")

class LogModel(Base):
    __tablename__ = "logs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    timestamp: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)

class AlertModel(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    timestamp: Mapped[str] = mapped_column(String(50))
    type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    message: Mapped[str] = mapped_column(Text)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)

class BackupModel(Base):
    __tablename__ = "backups"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    timestamp: Mapped[str] = mapped_column(String(50))
    config_type: Mapped[str] = mapped_column(String(20))
    content: Mapped[str] = mapped_column(Text)
    hash: Mapped[str] = mapped_column(String(100), default="")

class SecurityEventModel(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    timestamp: Mapped[str] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(50))
    source_mac: Mapped[str] = mapped_column(String(50), default="")
    source_ip: Mapped[str] = mapped_column(String(50), default="")
    port: Mapped[str] = mapped_column(String(50), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)


# --- WiFi Router Models ---

class WiFiSettings(Base):
    __tablename__ = "wifi_settings"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"), unique=True)
    mgmt_protocol: Mapped[str] = mapped_column(String(20), default="HTTPS")
    mgmt_port: Mapped[int] = mapped_column(Integer, default=443)
    wan_type: Mapped[str] = mapped_column(String(20), default="DHCP")
    isp_name: Mapped[str] = mapped_column(String(100), default="")
    wan_ip: Mapped[str] = mapped_column(String(50), default="")
    primary_dns: Mapped[str] = mapped_column(String(50), default="")
    secondary_dns: Mapped[str] = mapped_column(String(50), default="")
    gateway: Mapped[str] = mapped_column(String(50), default="")
    internet_status: Mapped[str] = mapped_column(String(20), default="online")
    ssid_24: Mapped[str] = mapped_column(String(100), default="")
    password_24_enc: Mapped[str] = mapped_column(String(200), default="")
    security_24: Mapped[str] = mapped_column(String(20), default="WPA2")
    channel_24: Mapped[str] = mapped_column(String(10), default="")
    channel_width_24: Mapped[str] = mapped_column(String(10), default="")
    tx_power_24: Mapped[str] = mapped_column(String(10), default="")
    enabled_24: Mapped[bool] = mapped_column(Boolean, default=True)
    ssid_5: Mapped[str] = mapped_column(String(100), default="")
    password_5_enc: Mapped[str] = mapped_column(String(200), default="")
    security_5: Mapped[str] = mapped_column(String(20), default="WPA2")
    channel_5: Mapped[str] = mapped_column(String(10), default="")
    channel_width_5: Mapped[str] = mapped_column(String(10), default="")
    tx_power_5: Mapped[str] = mapped_column(String(10), default="")
    enabled_5: Mapped[bool] = mapped_column(Boolean, default=True)
    firmware: Mapped[str] = mapped_column(String(50), default="")
    connected_clients: Mapped[int] = mapped_column(Integer, default=0)
    clients_24: Mapped[int] = mapped_column(Integer, default=0)
    clients_5: Mapped[int] = mapped_column(Integer, default=0)
    wan_throughput: Mapped[float] = mapped_column(Float, default=0)
    lan_throughput: Mapped[float] = mapped_column(Float, default=0)
    # DHCP pool
    dhcp_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    dhcp_start: Mapped[str] = mapped_column(String(50), default="")
    dhcp_end: Mapped[str] = mapped_column(String(50), default="")
    dhcp_lease_time: Mapped[str] = mapped_column(String(20), default="24h")
    # VLAN config
    vlan_id: Mapped[int] = mapped_column(Integer, default=1)
    # Band steering
    band_steering: Mapped[bool] = mapped_column(Boolean, default=False)
    # MAC filtering
    mac_filter_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mac_filter_mode: Mapped[str] = mapped_column(String(10), default="allow")  # allow, deny
    # Advanced
    wmm_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    short_gi_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    beamforming_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mu_mimo_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # VPN
    vpn_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    vpn_type: Mapped[str] = mapped_column(String(20), default="")
    vpn_server_ip: Mapped[str] = mapped_column(String(50), default="")


class WiFiClient(Base):
    __tablename__ = "wifi_clients"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(100), default="")
    ip: Mapped[str] = mapped_column(String(50), default="")
    mac: Mapped[str] = mapped_column(String(50), default="")
    band: Mapped[str] = mapped_column(String(10), default="5GHz")
    signal: Mapped[int] = mapped_column(Integer, default=0)
    connected_since: Mapped[str] = mapped_column(String(50), default="")
    upload_usage: Mapped[float] = mapped_column(Float, default=0)
    download_usage: Mapped[float] = mapped_column(Float, default=0)
    vendor: Mapped[str] = mapped_column(String(50), default="")


class WiFiGuestUser(Base):
    __tablename__ = "wifi_guest_users"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(100), default="")
    phone: Mapped[str] = mapped_column(String(50), default="")
    email: Mapped[str] = mapped_column(String(100), default="")
    login_time: Mapped[str] = mapped_column(String(50), default="")
    logout_time: Mapped[str] = mapped_column(String(50), default="")
    session_duration: Mapped[str] = mapped_column(String(50), default="")
    data_usage: Mapped[float] = mapped_column(Float, default=0)
    device_type: Mapped[str] = mapped_column(String(50), default="")


class WiFiSecurityEvent(Base):
    __tablename__ = "wifi_security_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    timestamp: Mapped[str] = mapped_column(String(50))
    event_type: Mapped[str] = mapped_column(String(50))
    source_mac: Mapped[str] = mapped_column(String(50), default="")
    source_ip: Mapped[str] = mapped_column(String(50), default="")
    details: Mapped[str] = mapped_column(Text, default="")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)


class WifiDhcpLease(Base):
    __tablename__ = "wifi_dhcp_leases"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    hostname: Mapped[str] = mapped_column(String(100), default="")
    ip: Mapped[str] = mapped_column(String(50), default="")
    mac: Mapped[str] = mapped_column(String(50), default="")
    lease_time: Mapped[str] = mapped_column(String(50), default="")
    expires: Mapped[str] = mapped_column(String(50), default="")
    lease_type: Mapped[str] = mapped_column(String(20), default="dynamic")  # dynamic, static, reservation
    vendor: Mapped[str] = mapped_column(String(100), default="")


class WifiFirewallRule(Base):
    __tablename__ = "wifi_firewall_rules"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(100), default="")
    action: Mapped[str] = mapped_column(String(20), default="allow")  # allow, deny
    protocol: Mapped[str] = mapped_column(String(10), default="TCP")
    source_ip: Mapped[str] = mapped_column(String(100), default="")
    source_port: Mapped[str] = mapped_column(String(20), default="")
    dest_ip: Mapped[str] = mapped_column(String(100), default="")
    dest_port: Mapped[str] = mapped_column(String(20), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    log_hits: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(Text, default="")


class WifiPortForward(Base):
    __tablename__ = "wifi_port_forwards"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    name: Mapped[str] = mapped_column(String(100), default="")
    protocol: Mapped[str] = mapped_column(String(10), default="TCP")
    external_port: Mapped[str] = mapped_column(String(20), default="")
    internal_ip: Mapped[str] = mapped_column(String(50), default="")
    internal_port: Mapped[str] = mapped_column(String(20), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(Text, default="")


class WifiMacFilter(Base):
    __tablename__ = "wifi_mac_filters"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(50), ForeignKey("devices.id"))
    mac: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(100), default="")
    action: Mapped[str] = mapped_column(String(10), default="allow")  # allow, deny
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


# --- Network Discovery Models ---

class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(Integer, default=0)
    router_id: Mapped[str] = mapped_column(String(50), default="")
    ip: Mapped[str] = mapped_column(String(50))
    mac: Mapped[str] = mapped_column(String(50), default="")
    hostname: Mapped[str] = mapped_column(String(200), default="")
    vendor: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(20), default="online")
    open_ports: Mapped[str] = mapped_column(Text, default="")
    response_time: Mapped[float] = mapped_column(Float, default=0)
    os_guess: Mapped[str] = mapped_column(String(100), default="")
    first_seen: Mapped[str] = mapped_column(String(50))
    last_seen: Mapped[str] = mapped_column(String(50))
    network_segment: Mapped[str] = mapped_column(String(50), default="")
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)
    is_duplicate_ip: Mapped[bool] = mapped_column(Boolean, default=False)
    is_duplicate_mac: Mapped[bool] = mapped_column(Boolean, default=False)


class NetworkScan(Base):
    __tablename__ = "network_scans"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    router_id: Mapped[str] = mapped_column(String(50), default="")
    network: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(20), default="manual")
    status: Mapped[str] = mapped_column(String(20), default="completed")
    duration_sec: Mapped[float] = mapped_column(Float, default=0)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    hosts_online: Mapped[int] = mapped_column(Integer, default=0)
    hosts_offline: Mapped[int] = mapped_column(Integer, default=0)
    hosts_unknown: Mapped[int] = mapped_column(Integer, default=0)
    new_devices: Mapped[int] = mapped_column(Integer, default=0)
    anomalies: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[str] = mapped_column(String(50))
    completed_at: Mapped[str] = mapped_column(String(50))
    error: Mapped[str] = mapped_column(Text, default="")


class SeedFlag(Base):
    __tablename__ = "_seed_flag"
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    seeded: Mapped[bool] = mapped_column(Boolean, default=False)


# --- Lookup functions ---

async def get_discovered_hosts(router_id: str = None) -> list[DiscoveredHost]:
    async with AsyncSessionLocal() as session:
        q = select(DiscoveredHost)
        if router_id:
            q = q.where(DiscoveredHost.router_id == router_id)
        q = q.order_by(DiscoveredHost.last_seen.desc())
        r = await session.execute(q)
        return list(r.scalars().all())

async def get_network_scans(limit: int = 20) -> list[NetworkScan]:
    async with AsyncSessionLocal() as session:
        q = select(NetworkScan).order_by(NetworkScan.id.desc()).limit(limit)
        r = await session.execute(q)
        return list(r.scalars().all())

async def get_previous_hosts(router_id: str) -> list[DiscoveredHost]:
    """Get the most recent full scan's hosts for anomaly detection."""
    async with AsyncSessionLocal() as session:
        latest_scan = (await session.execute(
            select(NetworkScan).where(NetworkScan.router_id == router_id)
            .order_by(NetworkScan.id.desc()).limit(1)
        )).scalar_one_or_none()
        if not latest_scan:
            return []
        hosts = await session.execute(
            select(DiscoveredHost).where(
                DiscoveredHost.scan_id == latest_scan.id,
                DiscoveredHost.router_id == router_id,
            )
        )
        return list(hosts.scalars().all())

async def save_scan(scan: NetworkScan) -> int:
    async with AsyncSessionLocal() as session:
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        return scan.id

async def save_hosts(hosts: list[DiscoveredHost]):
    async with AsyncSessionLocal() as session:
        for h in hosts:
            session.add(h)
        await session.commit()


# --- Init & Seed ---

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add ip column if not exists (migration for existing DBs)
        from sqlalchemy import inspect, text
        def _migrate(sync_conn):
            inspector = inspect(sync_conn)
            cols = [c["name"] for c in inspector.get_columns("interfaces")]
            if "ip" not in cols:
                sync_conn.execute(text("ALTER TABLE interfaces ADD COLUMN ip VARCHAR(50) NOT NULL DEFAULT ''"))
        await conn.run_sync(_migrate)

async def seed_interfaces(session):
    result = await session.execute(
        select(DeviceModel).where(DeviceModel.device_type == "WiFi Router")
    )
    routers = result.scalars().all()
    for router in routers:
        existing = await session.execute(
            select(InterfaceModel).where(InterfaceModel.device_id == router.id)
        )
        if existing.scalars().first():
            continue
        for name in ["Gi0/0", "Gi0/1", "Gi0/2", "Gi0/3"]:
            session.add(InterfaceModel(device_id=router.id, name=name))
    await session.flush()

async def seed_db():
    async with AsyncSessionLocal() as session:
        flag = await session.get(SeedFlag, 1)
        if flag and flag.seeded:
            # Still ensure interfaces exist for existing routers
            await seed_interfaces(session)
            await session.commit()
            return
        if not flag:
            session.add(SeedFlag(id=1, seeded=True))
        else:
            flag.seeded = True
        await seed_interfaces(session)
        await session.commit()


# --- Query Helpers ---

async def get_devices():
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(DeviceModel).order_by(DeviceModel.id))
        return r.scalars().all()

async def get_device(device_id: str):
    async with AsyncSessionLocal() as session:
        return await session.get(DeviceModel, device_id)

async def add_device_model(device: DeviceModel):
    async with AsyncSessionLocal() as session:
        session.add(device)
        await session.flush()
        return device

async def get_credentials(device_id: str):
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(DeviceCredential).where(DeviceCredential.device_id == device_id))
        return r.scalar_one_or_none()

async def save_credentials(cred: DeviceCredential):
    async with AsyncSessionLocal() as session:
        session.add(cred)
        await session.commit()

async def get_interfaces(device_id: str | None = None):
    async with AsyncSessionLocal() as session:
        q = select(InterfaceModel)
        if device_id:
            q = q.where(InterfaceModel.device_id == device_id)
        r = await session.execute(q.order_by(InterfaceModel.device_id, InterfaceModel.name))
        return r.scalars().all()

async def get_vlans():
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(VLANModel).order_by(VLANModel.id))
        return r.scalars().all()

async def get_logs(limit: int = 20):
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(LogModel).order_by(LogModel.id.desc()).limit(limit))
        return r.scalars().all()

async def get_alerts():
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(AlertModel).order_by(AlertModel.id.desc()))
        return r.scalars().all()

async def get_security_events():
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(SecurityEventModel).order_by(SecurityEventModel.id.desc()))
        return r.scalars().all()

async def get_dashboard_summary():
    async with AsyncSessionLocal() as session:
        devices = (await session.execute(select(DeviceModel))).scalars().all()
        interfaces = (await session.execute(select(InterfaceModel))).scalars().all()
        alerts = (await session.execute(select(AlertModel))).scalars().all()
        sec = (await session.execute(select(SecurityEventModel))).scalars().all()
        wifi_secs = (await session.execute(select(WiFiSecurityEvent))).scalars().all()
        wifi_clients = (await session.execute(select(WiFiClient))).scalars().all()

        total = len(devices)
        online = sum(1 for d in devices if d.status == "online")
        warning = sum(1 for d in devices if d.status == "warning")
        critical = sum(1 for d in devices if d.status == "critical")
        offline = sum(1 for d in devices if d.status == "offline")

        active_ports = sum(1 for i in interfaces if i.status == "up")
        shutdown_ports = sum(1 for i in interfaces if i.status == "shutdown")
        err_disabled = sum(1 for i in interfaces if i.status == "err-disabled")
        flapping = sum(1 for i in interfaces if i.status == "flapping")
        high_cpu = sum(1 for d in devices if d.cpu_usage > 80)
        high_mem = sum(1 for d in devices if d.memory_usage > 80)
        wifi_routers = sum(1 for d in devices if d.device_type == "WiFi Router")
        total_wifi_clients = len(wifi_clients)

        score = 100
        score -= critical * 10
        score -= warning * 5
        score -= offline * 5
        score -= err_disabled * 3
        score -= flapping * 3
        score = max(0, score)

        return {
            "health_score": score, "total_devices": total, "online_devices": online,
            "warning_devices": warning, "critical_devices": critical, "offline_devices": offline,
            "active_ports": active_ports, "shutdown_ports": shutdown_ports,
            "err_disabled_ports": err_disabled, "flapping_ports": flapping,
            "high_cpu_devices": high_cpu, "high_memory_devices": high_mem,
            "security_events": len(sec) + len(wifi_secs), "active_alerts": sum(1 for a in alerts if not a.acknowledged),
            "failed_logins": sum(1 for e in sec if e.event_type == "failed_login"),
            "unauthorized_macs": sum(1 for e in sec if e.event_type == "unauthorized_mac"),
            "wifi_routers": wifi_routers, "total_wifi_clients": total_wifi_clients,
        }


# --- WiFi Query Helpers ---

async def get_wifi_settings(device_id: str):
    async with AsyncSessionLocal() as session:
        r = await session.execute(select(WiFiSettings).where(WiFiSettings.device_id == device_id))
        return r.scalar_one_or_none()

async def save_wifi_settings(settings: WiFiSettings):
    async with AsyncSessionLocal() as session:
        existing = await session.execute(select(WiFiSettings).where(WiFiSettings.device_id == settings.device_id))
        ex = existing.scalar_one_or_none()
        if ex:
            for key in [c.name for c in WiFiSettings.__table__.columns if c.name != "id"]:
                setattr(ex, key, getattr(settings, key))
        else:
            session.add(settings)
        await session.commit()

async def get_wifi_clients(device_id: str | None = None):
    async with AsyncSessionLocal() as session:
        q = select(WiFiClient)
        if device_id:
            q = q.where(WiFiClient.device_id == device_id)
        r = await session.execute(q.order_by(WiFiClient.name))
        return r.scalars().all()

async def save_wifi_clients(device_id: str, clients: list[dict]):
    async with AsyncSessionLocal() as session:
        await session.execute(
            __import__("sqlalchemy").delete(WiFiClient).where(WiFiClient.device_id == device_id)
        )
        for c in clients:
            session.add(WiFiClient(
                device_id=device_id,
                name=c.get("name", ""),
                ip=c.get("ip", ""),
                mac=c.get("mac", ""),
                band=c.get("band", ""),
                signal=c.get("signal", 0),
            ))
        await session.commit()

async def save_interfaces(device_id: str, interfaces: list[dict]):
    async with AsyncSessionLocal() as session:
        await session.execute(
            __import__("sqlalchemy").delete(InterfaceModel).where(InterfaceModel.device_id == device_id)
        )
        for iface in interfaces:
            session.add(InterfaceModel(
                device_id=device_id,
                name=iface.get("name", ""),
                status=iface.get("status", "down"),
                vlan=iface.get("vlan", ""),
                speed=iface.get("speed", ""),
                duplex=iface.get("duplex", "auto"),
                mac=iface.get("mac", ""),
                ip=iface.get("ip", ""),
            ))
        await session.commit()

async def get_wifi_guests(device_id: str | None = None):
    async with AsyncSessionLocal() as session:
        q = select(WiFiGuestUser)
        if device_id:
            q = q.where(WiFiGuestUser.device_id == device_id)
        r = await session.execute(q.order_by(WiFiGuestUser.login_time.desc()))
        return r.scalars().all()

async def get_wifi_security_events(device_id: str | None = None):
    async with AsyncSessionLocal() as session:
        q = select(WiFiSecurityEvent)
        if device_id:
            q = q.where(WiFiSecurityEvent.device_id == device_id)
        r = await session.execute(q.order_by(WiFiSecurityEvent.timestamp.desc()))
        return r.scalars().all()


# --- New WiFi Detail Query Helpers ---

async def get_wifi_dhcp_leases(device_id: str):
    async with AsyncSessionLocal() as session:
        q = select(WifiDhcpLease).where(WifiDhcpLease.device_id == device_id)
        r = await session.execute(q.order_by(WifiDhcpLease.ip))
        return r.scalars().all()

async def save_wifi_dhcp_leases(device_id: str, leases: list[dict]):
    async with AsyncSessionLocal() as session:
        await session.execute(
            __import__("sqlalchemy").delete(WifiDhcpLease).where(WifiDhcpLease.device_id == device_id)
        )
        for l in leases:
            session.add(WifiDhcpLease(device_id=device_id, **l))
        await session.commit()

async def get_wifi_firewall_rules(device_id: str):
    async with AsyncSessionLocal() as session:
        q = select(WifiFirewallRule).where(WifiFirewallRule.device_id == device_id)
        r = await session.execute(q.order_by(WifiFirewallRule.name))
        return r.scalars().all()

async def save_wifi_firewall_rules(device_id: str, rules: list[dict]):
    async with AsyncSessionLocal() as session:
        await session.execute(
            __import__("sqlalchemy").delete(WifiFirewallRule).where(WifiFirewallRule.device_id == device_id)
        )
        for rule in rules:
            session.add(WifiFirewallRule(device_id=device_id, **rule))
        await session.commit()

async def get_wifi_port_forwards(device_id: str):
    async with AsyncSessionLocal() as session:
        q = select(WifiPortForward).where(WifiPortForward.device_id == device_id)
        r = await session.execute(q.order_by(WifiPortForward.name))
        return r.scalars().all()

async def save_wifi_port_forwards(device_id: str, forwards: list[dict]):
    async with AsyncSessionLocal() as session:
        await session.execute(
            __import__("sqlalchemy").delete(WifiPortForward).where(WifiPortForward.device_id == device_id)
        )
        for fwd in forwards:
            session.add(WifiPortForward(device_id=device_id, **fwd))
        await session.commit()

async def get_wifi_mac_filters(device_id: str):
    async with AsyncSessionLocal() as session:
        q = select(WifiMacFilter).where(WifiMacFilter.device_id == device_id)
        r = await session.execute(q.order_by(WifiMacFilter.mac))
        return r.scalars().all()

async def save_wifi_mac_filters(device_id: str, filters: list[dict]):
    async with AsyncSessionLocal() as session:
        await session.execute(
            __import__("sqlalchemy").delete(WifiMacFilter).where(WifiMacFilter.device_id == device_id)
        )
        for f in filters:
            session.add(WifiMacFilter(device_id=device_id, **f))
        await session.commit()

def decrypt_wifi_password(encrypted: str) -> str:
    if not encrypted:
        return ""
    try:
        return decrypt_cred(encrypted)
    except Exception:
        return "***"
