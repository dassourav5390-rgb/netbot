"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";

type Device = {
  id: string; hostname: string; vendor: string; model: string; serial: string; version: string
  category: string; device_type: string; ip: string; status: string
  cpu_usage: number; memory_usage: number; temperature: number
  uptime: string; last_seen: string; interface_errors: number; active_alerts: number
  location: string; description: string; connection_method: string; tags: string; health_score: number
};
type Interface = { id: number; device_id: string; name: string; status: string; vlan: string; speed: string; errors: number; drops: number; bandwidth_usage: number; description: string; mac: string; ip: string; port_security: boolean; bpdu_guard: boolean; stp_state: string; is_trunk: boolean };

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const API_KEY = process.env.NEXT_PUBLIC_NETBOT_API_KEY || "";

function apiFetch(input: RequestInfo | URL, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  if (API_KEY) headers.set("X-NetBot-Api-Key", API_KEY);
  return fetch(input, { ...init, headers });
}

function statusColor(s: string) {
  switch (s) {
    case "online": return "bg-green-500";
    case "warning": return "bg-yellow-500";
    case "critical": return "bg-red-500";
    default: return "bg-zinc-500";
  }
}

function signalColor(s: number) {
  if (s >= -50) return "text-green-400";
  if (s >= -70) return "text-yellow-400";
  return "text-red-400";
}

function ToastContainer({ toasts }: { toasts: {id: number; message: string; type: "online" | "offline"}[] }) {
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map(t => (
        <div key={t.id}
          className={`flex items-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium shadow-lg ${
            t.type === "online"
              ? "border-green-700/50 bg-green-900/80 text-green-200"
              : "border-red-700/50 bg-red-900/80 text-red-200"
          }`}>
          <span className={`inline-block h-2 w-2 rounded-full ${t.type === "online" ? "bg-green-400" : "bg-red-400"}`} />
          {t.message}
        </div>
      ))}
    </div>
  );
}

export default function DeviceDetail() {
  const params = useParams();
  const router = useRouter();
  const deviceId = params.id as string;

  const [device, setDevice] = useState<Device | null>(null);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);

  // WiFi state
  const [wifiClients, setWifiClients] = useState<any[]>([]);
  const [wifiSettings, setWifiSettings] = useState<any>(null);
  const [wifiHealth, setWifiHealth] = useState<any>(null);
  const [wifiLoading, setWifiLoading] = useState(false);
  const [wifiError, setWifiError] = useState<string | null>(null);
  const [dhcpLeases, setDhcpLeases] = useState<any[]>([]);
  const [firewallRules, setFirewallRules] = useState<any[]>([]);
  const [portForwards, setPortForwards] = useState<any[]>([]);
  const [macFilters, setMacFilters] = useState<any[]>([]);
  const [wifiTab, setWifiTab] = useState<string>("devices");
  const [deleting, setDeleting] = useState(false);

  // Live interfaces from SSH
  const [liveInterfaces, setLiveInterfaces] = useState<any[]>([]);
  const [interfacesLoading, setInterfacesLoading] = useState(false);
  const [interfacesError, setInterfacesError] = useState<string | null>(null);

  // SSH Console
  const [sshCommand, setSshCommand] = useState("");
  const [sshOutput, setSshOutput] = useState("");
  const [sshLoading, setSshLoading] = useState(false);

  // Toast notifications for status changes
  const [toasts, setToasts] = useState<{id: number; message: string; type: "online" | "offline"}[]>([]);
  const prevStatusRef = useRef<string>("");
  const lastAlertIdRef = useRef(0);
  let toastId = useRef(0);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const unlockAudio = () => {
    if (audioCtxRef.current) return;
    try {
      const AC = window.AudioContext || (window as any).webkitAudioContext;
      const ctx = new AC();
      const buf = ctx.createBuffer(1, 1, 22050);
      const src = ctx.createBufferSource();
      src.buffer = buf;
      src.connect(ctx.destination);
      src.start();
      audioCtxRef.current = ctx;
    } catch {}
  };
  useEffect(() => {
    const handler = () => unlockAudio();
    document.addEventListener("click", handler, { once: true });
    document.addEventListener("touchstart", handler, { once: true });
    document.addEventListener("keydown", handler, { once: true });
    return () => {
      document.removeEventListener("click", handler);
      document.removeEventListener("touchstart", handler);
      document.removeEventListener("keydown", handler);
    };
  }, []);

  const _playTone = (type: "online" | "offline") => {
    const ctx = audioCtxRef.current;
    if (!ctx) return;
    try {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      gain.gain.value = 0.3;
      if (type === "offline") {
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(440, ctx.currentTime);
        osc.frequency.linearRampToValueAtTime(220, ctx.currentTime + 0.3);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.4);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.4);
      } else {
        osc.type = "sine";
        osc.frequency.setValueAtTime(523, ctx.currentTime);
        osc.frequency.linearRampToValueAtTime(659, ctx.currentTime + 0.15);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + 0.3);
        osc.start(ctx.currentTime);
        osc.stop(ctx.currentTime + 0.3);
      }
    } catch {}
  };

  const addToast = (message: string, type: "online" | "offline") => {
    const id = ++toastId.current;
    setToasts(prev => [...prev, {id, message, type}]);
    _playTone(type);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 5000);
  };

  useEffect(() => {
    if (!deviceId) return;
    setLoading(true);
    setNotFound(false);
    const fetchDevice = () => Promise.all([
      apiFetch(`${API}/api/devices/${deviceId}`).then(async r => {
        if (r.status === 404) { setNotFound(true); return null; }
        return r.json();
      }),
      apiFetch(`${API}/api/interfaces`).then(r => r.json()),
    ]).then(([dev, ifs]) => {
      if (dev) {
        const prev = prevStatusRef.current;
        if (prev && prev !== dev.status && (dev.status === "online" || dev.status === "offline")) {
          addToast(`${dev.hostname} is now ${dev.status}`, dev.status);
        }
        prevStatusRef.current = dev.status;
        setDevice(dev);
      }
      setInterfaces(Array.isArray(ifs) ? ifs.filter((i: Interface) => i.device_id === deviceId) : []);
      setLoading(false);
    }).catch(() => setLoading(false));
    fetchDevice();
    refreshInterfaces();
    const interval = setInterval(fetchDevice, 5000);
    return () => clearInterval(interval);
  }, [deviceId]);

  // Poll alerts every 10s and notify on new interface-down events
  useEffect(() => {
    let initialized = false;
    const interval = setInterval(async () => {
      try {
        const res = await apiFetch(`${API}/api/alerts`);
        const alerts: any[] = await res.json();
        if (!initialized) {
          initialized = true;
          if (alerts.length > 0) lastAlertIdRef.current = alerts[0].id;
          return;
        }
        for (const a of alerts) {
          if (a.id > lastAlertIdRef.current && !a.acknowledged) {
            lastAlertIdRef.current = a.id;
            if (a.type === "interface_down") {
              addToast(a.message, "offline");
            } else if (a.type === "interface_up") {
              addToast(a.message, "online");
            }
          }
        }
      } catch {}
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  const refreshInterfaces = async () => {
    setInterfacesLoading(true);
    setInterfacesError(null);
    try {
      const res = await apiFetch(`${API}/api/devices/${deviceId}/interfaces/refresh`, { method: "POST" });
      if (!res.ok) { const err = await res.json().catch(() => ({})); setInterfacesError(err.detail || `Failed (${res.status})`); setInterfacesLoading(false); return; }
      const data = await res.json();
      setLiveInterfaces(data.interfaces || []);
    } catch { setInterfacesError("Network error"); }
    setInterfacesLoading(false);
  };

  const fetchWifiData = useCallback(async () => {
    if (device?.device_type !== "WiFi Router") {
      setWifiClients([]); setWifiSettings(null); setWifiHealth(null);
      setDhcpLeases([]); setFirewallRules([]); setPortForwards([]); setMacFilters([]);
      setWifiError(null); setWifiLoading(false);
      return;
    }
    setWifiLoading(true);
    setWifiError(null);
    const errors: string[] = [];
    const safeFetch = (url: string) => apiFetch(url).catch(() => { errors.push(url.split("/").pop() || "request"); return null; });
    await Promise.all([
      safeFetch(`${API}/api/wifi/${deviceId}/clients`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setWifiClients(Array.isArray(d) ? d : []); }
        else if (r) errors.push(`Clients: ${r.status}`);
      }),
      safeFetch(`${API}/api/wifi/${deviceId}/settings`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setWifiSettings(d); }
        else if (r && r.status !== 404) errors.push(`Settings: ${r.status}`);
      }),
      safeFetch(`${API}/api/wifi/${deviceId}/health`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setWifiHealth(d); }
        else if (r && r.status !== 404) errors.push(`Health: ${r.status}`);
      }),
      safeFetch(`${API}/api/wifi/${deviceId}/dhcp-leases`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setDhcpLeases(Array.isArray(d) ? d : []); }
        else if (r) errors.push(`DHCP: ${r.status}`);
      }),
      safeFetch(`${API}/api/wifi/${deviceId}/firewall-rules`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setFirewallRules(Array.isArray(d) ? d : []); }
        else if (r) errors.push(`Firewall: ${r.status}`);
      }),
      safeFetch(`${API}/api/wifi/${deviceId}/port-forwards`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setPortForwards(Array.isArray(d) ? d : []); }
        else if (r) errors.push(`PortFW: ${r.status}`);
      }),
      safeFetch(`${API}/api/wifi/${deviceId}/mac-filters`).then(async r => {
        if (r && r.ok) { const d = await r.json(); setMacFilters(Array.isArray(d) ? d : []); }
        else if (r) errors.push(`MACFilter: ${r.status}`);
      }),
    ]).finally(() => {
      if (errors.length) setWifiError("Failed to load: " + errors.join(", "));
      setWifiLoading(false);
    });
  }, [device, deviceId]);

  useEffect(() => { fetchWifiData(); }, [fetchWifiData]);

  const [syncing, setSyncing] = useState(false);
  const [blockingMacs, setBlockingMacs] = useState<Set<string>>(new Set());

  const handleBlock = async (mac: string, band: string, name: string) => {
    if (!window.confirm(`Block ${mac}? This client will be disconnected and prevented from reconnecting.`)) return;
    setBlockingMacs(prev => new Set(prev).add(mac));
    setWifiError(null);
    try {
      const r = await apiFetch(`${API}/api/wifi/${deviceId}/block-client`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mac, band, name }),
      });
      if (!r.ok) { const e = await r.json().catch(() => ({})); setWifiError(e.detail || `Failed to block ${mac}`); }
      else { await fetchWifiData(); }
    } catch { setWifiError(`Network error blocking ${mac}`); }
    setBlockingMacs(prev => { const next = new Set(prev); next.delete(mac); return next; });
  };

  const handleUnblock = async (mac: string, band: string) => {
    if (!window.confirm(`Unblock ${mac}? This client will be allowed to reconnect.`)) return;
    setBlockingMacs(prev => new Set(prev).add(mac));
    setWifiError(null);
    try {
      const r = await apiFetch(`${API}/api/wifi/${deviceId}/unblock-client`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mac, band }),
      });
      if (!r.ok) { const e = await r.json().catch(() => ({})); setWifiError(e.detail || `Failed to unblock ${mac}`); }
      else { await fetchWifiData(); }
    } catch { setWifiError(`Network error unblocking ${mac}`); }
    setBlockingMacs(prev => { const next = new Set(prev); next.delete(mac); return next; });
  };

  const blockedMacs = new Set(macFilters.filter((f: any) => f.action === "deny").map((f: any) => f.mac.toUpperCase()));

  const handleRefresh = async () => {
    setSyncing(true);
    setWifiError(null);
    try {
      const r = await apiFetch(`${API}/api/wifi/${deviceId}/sync`, { method: "POST" });
      if (r.ok) { await fetchWifiData(); }
      else { const e = await r.json().catch(() => ({})); setWifiError(e.detail || `Sync failed (${r.status})`); }
    } catch { setWifiError("Network error during sync"); }
    setSyncing(false);
  };

  const handleExecuteCommand = async (cmd?: string) => {
    const command = cmd || sshCommand;
    if (!command.trim()) return;
    setSshLoading(true);
    setSshOutput(prev => prev + `\n${device?.hostname || "Switch"}# ${command}\n`);
    try {
      const res = await apiFetch(`${API}/api/devices/${deviceId}/execute`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command }),
      });
      if (!res.ok) { const err = await res.json(); setSshOutput(prev => prev + `Error: ${err.detail || "Command failed"}\n`); return; }
      const data = await res.json();
      setSshOutput(prev => prev + data.output + "\n");
    } catch { setSshOutput(prev => prev + "Error: Unable to reach backend\n"); }
    setSshLoading(false);
  };

  const handleDelete = async () => {
    if (!window.confirm(`Delete device "${device?.hostname}"?\n\nAll WiFi settings, clients, leases, and rules will be permanently removed.`)) return;
    setDeleting(true);
    try {
      const r = await apiFetch(`${API}/api/devices/${deviceId}`, { method: "DELETE" });
      if (!r.ok) { alert("Delete failed"); setDeleting(false); return; }
      router.push("/");
    } catch {
      alert("Network error");
      setDeleting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex h-screen items-center justify-center bg-zinc-950">
        <div className="flex items-center gap-3 text-zinc-400">
          <div className="animate-spin inline-block h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full" />
          Loading device...
        </div>
      </div>
    );
  }

  if (notFound || !device) {
    return (
      <div className="flex h-screen flex-col items-center justify-center bg-zinc-950 gap-4">
        <div className="text-6xl">🔍</div>
        <h1 className="text-xl font-semibold text-zinc-300">Device Not Found</h1>
        <p className="text-sm text-zinc-500">The device &quot;{deviceId}&quot; does not exist.</p>
        <button onClick={() => router.push("/")} className="rounded-lg bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-500 transition-colors">
          Back to Dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-zinc-800 px-6 py-3">
        <div className="flex items-center gap-3">
          <button onClick={() => router.push("/")} className="text-zinc-500 hover:text-zinc-300 transition-colors">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
            </svg>
          </button>
          <span className={`inline-block h-2.5 w-2.5 rounded-full ${statusColor(device.status)}`} />
          <div>
            <h1 className="text-lg font-semibold tracking-tight">{device.hostname}</h1>
            <p className="text-xs text-zinc-500">{device.vendor} {device.model} &bull; {device.ip}</p>
          </div>
        </div>
        <div className="flex items-center gap-3 text-sm text-zinc-500">
          <button onClick={() => router.push(`/?chat=1&device=${deviceId}`)}
            className="rounded-lg bg-emerald-600/10 px-3 py-1.5 text-xs text-emerald-400 hover:bg-emerald-600/20 transition-colors flex items-center gap-1.5">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            Chat
          </button>
          <span>CPU: {device.cpu_usage}%</span>
          <span>MEM: {device.memory_usage}%</span>
          <span>Temp: {device.temperature}°C</span>
          <span>Uptime: {device.uptime}</span>
          {wifiHealth && (
            <>
              <span className="text-emerald-400">Clients: {wifiHealth.connected_clients}</span>
              <span className="text-blue-400">Health: {wifiHealth.health_score}/100</span>
            </>
          )}
        </div>
      </header>

      <div className="max-w-6xl mx-auto p-6 space-y-6">
        {/* Quick Actions */}
        <div className="flex gap-2">
          <button className="rounded-lg bg-blue-600/10 px-4 py-2 text-xs text-blue-400 hover:bg-blue-600/20">Connect</button>
          <button className="rounded-lg bg-zinc-800 px-4 py-2 text-xs text-zinc-400 hover:bg-zinc-700">Backup Config</button>
          <button className="rounded-lg bg-zinc-800 px-4 py-2 text-xs text-zinc-400 hover:bg-zinc-700">Run Diagnostics</button>
          <button className="rounded-lg bg-zinc-800 px-4 py-2 text-xs text-zinc-400 hover:bg-zinc-700">Show Logs</button>
          <button className="rounded-lg bg-zinc-800 px-4 py-2 text-xs text-zinc-400 hover:bg-zinc-700">Compliance Check</button>
          <button onClick={handleRefresh} disabled={syncing}
            className="rounded-lg bg-zinc-800 px-4 py-2 text-xs text-zinc-400 hover:bg-zinc-700 disabled:opacity-50 flex items-center gap-1.5">
            <svg className={`h-3.5 w-3.5 ${syncing ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {syncing ? "Syncing..." : "Refresh"}
          </button>
          <div className="flex-1" />
          <button onClick={handleDelete} disabled={deleting}
            className="rounded-lg bg-red-600/10 px-4 py-2 text-xs text-red-400 hover:bg-red-600/20 disabled:opacity-50">
            {deleting ? "Deleting..." : "Delete"}
          </button>
          <span className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-medium ${device.status === "online" ? "text-green-400 bg-green-500/10" : device.status === "warning" ? "text-yellow-400 bg-yellow-500/10" : device.status === "critical" ? "text-red-400 bg-red-500/10" : "text-zinc-400 bg-zinc-500/10"}`}>
            <span className={`inline-block h-1.5 w-1.5 rounded-full ${statusColor(device.status)}`} />
            {device.status}
          </span>
        </div>

        {/* Info Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">General</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-zinc-400">Device ID</span><span className="text-zinc-200 font-mono text-xs">{device.id}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Category</span><span className="text-zinc-200">{device.category}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Type</span><span className="text-zinc-200">{device.device_type}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Vendor</span><span className="text-zinc-200">{device.vendor}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Model</span><span className="text-zinc-200">{device.model || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Serial</span><span className="text-zinc-200 font-mono text-xs">{device.serial || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Version</span><span className="text-zinc-200">{device.version || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Firmware</span><span className="text-zinc-200">{wifiSettings?.firmware || "—"}</span></div>
            </div>
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Connection</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-zinc-400">IP Address</span><span className="text-zinc-200 font-mono text-xs">{device.ip}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Method</span><span className="text-zinc-200">{device.connection_method || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Location</span><span className="text-zinc-200">{device.location || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Tags</span><span className="text-zinc-200">{device.tags || "—"}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Last Seen</span><span className="text-zinc-200">{device.last_seen}</span></div>
            </div>
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Performance</h3>
            <div className="space-y-3 text-sm">
              <div>
                <div className="flex justify-between mb-1"><span className="text-zinc-400">CPU</span><span className={device.cpu_usage > 80 ? "text-red-400" : device.cpu_usage > 60 ? "text-yellow-400" : "text-green-400"}>{device.cpu_usage}%</span></div>
                <div className="h-1.5 w-full rounded-full bg-zinc-800"><div className={`h-full rounded-full ${device.cpu_usage > 80 ? "bg-red-500" : device.cpu_usage > 60 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${device.cpu_usage}%` }} /></div>
              </div>
              <div>
                <div className="flex justify-between mb-1"><span className="text-zinc-400">Memory</span><span className={device.memory_usage > 80 ? "text-red-400" : device.memory_usage > 60 ? "text-yellow-400" : "text-green-400"}>{device.memory_usage}%</span></div>
                <div className="h-1.5 w-full rounded-full bg-zinc-800"><div className={`h-full rounded-full ${device.memory_usage > 80 ? "bg-red-500" : device.memory_usage > 60 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${device.memory_usage}%` }} /></div>
              </div>
              <div className="flex justify-between"><span className="text-zinc-400">Temperature</span><span className="text-zinc-200">{device.temperature}°C</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Uptime</span><span className="text-zinc-200">{device.uptime}</span></div>
            </div>
          </div>
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Health</h3>
            <div className="space-y-2 text-sm">
              <div className="flex flex-col items-center justify-center py-2">
                <div className={`text-4xl font-bold ${device.health_score >= 80 ? "text-green-400" : device.health_score >= 50 ? "text-yellow-400" : "text-red-400"}`}>{device.health_score}</div>
                <div className="text-xs text-zinc-500">/100 Health Score</div>
              </div>
              <div className="flex justify-between"><span className="text-zinc-400">Interface Errors</span><span className={device.interface_errors > 0 ? "text-red-400" : "text-green-400"}>{device.interface_errors}</span></div>
              <div className="flex justify-between"><span className="text-zinc-400">Active Alerts</span><span className={device.active_alerts > 0 ? "text-red-400" : "text-green-400"}>{device.active_alerts}</span></div>
            </div>
          </div>
        </div>

        {/* Description */}
        {device.description && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-2">Description</h3>
            <p className="text-sm text-zinc-300">{device.description}</p>
          </div>
        )}

        {/* Interfaces Table */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider">Interfaces {liveInterfaces.length > 0 ? `(${liveInterfaces.length})` : ""}</h2>
            <button onClick={refreshInterfaces} disabled={interfacesLoading}
              className="flex items-center gap-1.5 rounded-lg border border-zinc-700 px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-800 transition-colors disabled:opacity-50">
              <svg className={`h-3.5 w-3.5 ${interfacesLoading ? "animate-spin" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {interfacesLoading ? "SSH..." : "Refresh"}
            </button>
          </div>
          {interfacesError && (
            <div className="rounded-lg border border-red-800 bg-red-900/20 p-3 mb-3">
              <p className="text-xs text-red-400">{interfacesError}</p>
            </div>
          )}
          <div className="overflow-x-auto rounded-xl border border-zinc-800">
            <table className="w-full text-sm">
              <thead><tr className="border-b border-zinc-800 text-left text-xs text-zinc-500">
                <th className="px-4 py-3 font-medium">Port</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">VLAN</th>
                <th className="px-4 py-3 font-medium">Duplex</th>
                <th className="px-4 py-3 font-medium">Speed</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">Connected</th>
              </tr></thead>
              <tbody>
                {liveInterfaces.length === 0 ? (
                  <tr><td colSpan={7} className="px-4 py-6 text-center text-sm text-zinc-600">
                    {interfacesLoading ? "Refreshing via SSH..." : "No interfaces data. Click Refresh to pull from device."}
                  </td></tr>
                ) : (
                  liveInterfaces.map((iface: any, idx: number) => (
                    <tr key={idx} className="border-b border-zinc-800/50 hover:bg-zinc-900/50">
                      <td className="px-4 py-3 font-medium text-zinc-200 font-mono text-xs">{iface.port}</td>
                      <td className="px-4 py-3">
                        {iface.status === "up" || iface.status === "connected" ? (
                          <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium text-green-400 bg-green-500/10">
                            <span className="inline-block h-1.5 w-1.5 rounded-full bg-green-500" />
                            Up
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium text-zinc-400 bg-zinc-700/50">
                            <span className="inline-block h-1.5 w-1.5 rounded-full bg-zinc-500" />
                            {iface.status}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-zinc-400 font-mono text-xs">{iface.vlan || "—"}</td>
                      <td className="px-4 py-3 text-zinc-400 text-xs">{iface.duplex || "—"}</td>
                      <td className="px-4 py-3 text-zinc-400 text-xs">{iface.speed || "—"}</td>
                      <td className="px-4 py-3 text-zinc-500 text-xs max-w-[200px] truncate">{iface.type || "—"}</td>
                      <td className="px-4 py-3 text-xs">
                        {iface.connected_count > 0 ? (
                          <span className="group relative cursor-help">
                            <span className="text-emerald-400 font-medium">{iface.connected_count} device{iface.connected_count > 1 ? "s" : ""}</span>
                            <span className="invisible group-hover:visible absolute z-10 bottom-full left-0 mb-1 w-56 rounded-lg border border-zinc-700 bg-zinc-900 p-2 shadow-xl text-[10px] text-zinc-300 font-mono whitespace-normal">
                              {iface.connected_macs.map((m: string, mi: number) => (
                                <span key={mi} className="block truncate">{mi + 1}. {m}</span>
                              ))}
                            </span>
                          </span>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* SSH Console */}
        {device.device_type !== "WiFi Router" && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider">SSH Console</h2>
              <span className="text-xs text-zinc-600">Privileged EXEC mode</span>
            </div>

            {/* Quick Commands */}
            <div className="flex flex-wrap gap-1.5 mb-3">
              {["show running-config", "show interfaces", "show vlan brief", "show mac address-table", "show ip interface brief", "show spanning-tree", "show cdp neighbors"].map(cmd => (
                <button key={cmd} onClick={() => handleExecuteCommand(cmd)}
                  className="rounded-lg bg-zinc-800 px-2.5 py-1 text-[10px] text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200 transition-colors whitespace-nowrap">
                  {cmd}
                </button>
              ))}
            </div>

            {/* Terminal Output */}
            <div className="mb-3 rounded-lg bg-zinc-950 border border-zinc-800">
              <pre className="h-64 overflow-y-auto p-4 text-xs font-mono text-green-400 leading-relaxed whitespace-pre-wrap">
                {sshOutput || "Enter a command below or click a quick command button..."}
              </pre>
            </div>

            {/* Command Input */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-emerald-400 font-mono whitespace-nowrap">{device?.hostname || "Switch"}#</span>
              <input value={sshCommand} onChange={e => setSshCommand(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && !sshLoading) handleExecuteCommand(); }}
                placeholder="Enter command..."
                className="flex-1 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 font-mono placeholder-zinc-600 outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20" />
              <button onClick={() => handleExecuteCommand()} disabled={sshLoading}
                className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-medium text-white hover:bg-emerald-500 transition-colors disabled:opacity-50">
                {sshLoading ? <><div className="animate-spin inline-block h-3 w-3 border-2 border-white border-t-transparent rounded-full" /> Run</> : "Run"}
              </button>
              {sshOutput && (
                <button onClick={() => setSshOutput("")}
                  className="rounded-lg border border-zinc-700 px-3 py-2 text-xs text-zinc-500 hover:bg-zinc-800 transition-colors">
                  Clear
                </button>
              )}
            </div>
          </div>
        )}

        {/* WiFi Router Detail */}
        {device.device_type === "WiFi Router" && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider">Wi-Fi Configuration</h2>
              {wifiHealth && (
                <div className="flex items-center gap-3 text-xs">
                  <span className="text-emerald-400">Clients: {wifiHealth.connected_clients}</span>
                  <span className="text-blue-400">Health: {wifiHealth.health_score}/100</span>
                </div>
              )}
            </div>

            {wifiLoading && (
              <div className="flex items-center gap-2 text-xs text-zinc-500 py-4">
                <div className="animate-spin inline-block h-3 w-3 border-2 border-emerald-500 border-t-transparent rounded-full" />
                Loading WiFi data...
              </div>
            )}
            {wifiError && (
              <div className="rounded-lg border border-red-800 bg-red-900/20 p-3 mb-3">
                <p className="text-xs text-red-400">{wifiError}</p>
              </div>
            )}

            {/* Settings Grid */}
            {wifiSettings && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">Internet</span>
                  <div className={`font-medium ${wifiSettings.internet_status === "online" ? "text-green-400" : "text-red-400"}`}>{wifiSettings.internet_status}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">2.4GHz SSID</span>
                  <div className="font-medium text-zinc-200">{wifiSettings.ssid_24 || "—"} {wifiSettings.enabled_24 ? "" : <span className="text-red-400">(off)</span>}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">2.4GHz Password</span>
                  <div className="font-medium text-zinc-200 font-mono">{wifiSettings.password_24_enc ? "••••••••" : "—"}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">5GHz SSID</span>
                  <div className="font-medium text-zinc-200">{wifiSettings.ssid_5 || "—"} {wifiSettings.enabled_5 ? "" : <span className="text-red-400">(off)</span>}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">5GHz Password</span>
                  <div className="font-medium text-zinc-200 font-mono">{wifiSettings.password_5_enc ? "••••••••" : "—"}</div>
                </div>
              </div>
            )}

            {/* DHCP Pool Info */}
            {wifiSettings && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-4">
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">DHCP</span>
                  <div className={`font-medium ${wifiSettings.dhcp_enabled ? "text-green-400" : "text-red-400"}`}>{wifiSettings.dhcp_enabled ? "Enabled" : "Disabled"}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">DHCP Pool</span>
                  <div className="font-medium text-zinc-200">{wifiSettings.dhcp_start || "—"} – {wifiSettings.dhcp_end || "—"}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">Lease Time</span>
                  <div className="font-medium text-zinc-200">{wifiSettings.dhcp_lease_time || "—"}</div>
                </div>
                <div className="rounded-lg bg-zinc-800/50 p-3">
                  <span className="text-zinc-500">VLAN ID</span>
                  <div className="font-medium text-zinc-200">{wifiSettings.vlan_id || 1}</div>
                </div>
              </div>
            )}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-zinc-800 mb-3">
              {["devices", "firewall", "forwards", "macfilters"].map(tab => (
                <button key={tab} onClick={() => setWifiTab(tab)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-t-lg transition-colors ${
                    wifiTab === tab ? "bg-zinc-800 text-zinc-200 border-b-2 border-blue-500" : "text-zinc-500 hover:text-zinc-300"
                  }`}>
                  {tab === "devices" ? `Clients List` : tab === "firewall" ? "Firewall" : tab === "forwards" ? "Port Forwards" : "MAC Filters"}
                </button>
              ))}
            </div>

            {/* Tab: Clients List (real-time connected clients) */}
            {wifiTab === "devices" && (
              <div>
                <h4 className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">Clients List {wifiClients.length > 0 ? `(${wifiClients.length})` : ""}</h4>
                {wifiClients.length > 0 ? (
                  <div className="overflow-x-auto rounded-lg border border-zinc-800">
                    <table className="w-full text-xs">
                      <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                        <th className="px-3 py-2 font-medium">Hostname</th>
                        <th className="px-3 py-2 font-medium">IP</th>
                        <th className="px-3 py-2 font-medium">MAC</th>
                        <th className="px-3 py-2 font-medium">Signal</th>
                        <th className="px-3 py-2 font-medium">Band</th>
                        <th className="px-3 py-2 font-medium">Action</th>
                      </tr></thead>
                      <tbody>
                        {(() => {
                          const hostnameMap: Record<string, string> = {};
                          dhcpLeases.forEach((l: any) => {
                            if (l.hostname) { hostnameMap[l.ip] = l.hostname; hostnameMap[l.mac] = l.hostname; }
                          });
                          const bandFromMac = (mac: string): string => {
                            if (!mac) return "2.4GHz";
                            const clean = mac.replace(/-/g, ":").toLowerCase();
                            let sum = 0;
                            for (const octet of clean.split(":")) {
                              sum += parseInt(octet, 16);
                            }
                            return sum % 2 === 1 ? "5GHz" : "2.4GHz";
                          };
                          return wifiClients.map((c: any) => {
                            const isBlocked = blockedMacs.has((c.mac || '').toUpperCase());
                            const isBlocking = blockingMacs.has((c.mac || '').toUpperCase());
                            const hostname = hostnameMap[c.ip] || hostnameMap[c.mac] || c.name;
                            const band = c.band || bandFromMac(c.mac);
                            return (
                            <tr key={c.id} className="border-b border-zinc-800/50">
                              <td className="px-3 py-2 text-zinc-200">{hostname}</td>
                              <td className="px-3 py-2 text-zinc-400 font-mono">{c.ip}</td>
                              <td className="px-3 py-2 text-zinc-500 font-mono">{c.mac}</td>
                              <td className={`px-3 py-2 font-mono ${signalColor(c.signal)}`}>{c.signal} dBm</td>
                              <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${band === "5GHz" ? "bg-blue-500/10 text-blue-400" : "bg-amber-500/10 text-amber-400"}`}>{band}</span></td>
                              <td className="px-3 py-2">
                                {c.mac ? (
                                  isBlocked ? (
                                    <button onClick={() => handleUnblock(c.mac, band)} disabled={isBlocking}
                                      className="rounded bg-emerald-600/20 px-2 py-1 text-[10px] text-emerald-400 hover:bg-emerald-600/30 disabled:opacity-50">
                                      {isBlocking ? "..." : "Unblock"}
                                    </button>
                                  ) : (
                                    <button onClick={() => handleBlock(c.mac, band, c.name)} disabled={isBlocking}
                                      className="rounded bg-red-600/20 px-2 py-1 text-[10px] text-red-400 hover:bg-red-600/30 disabled:opacity-50">
                                      {isBlocking ? "..." : "Block"}
                                    </button>
                                  )
                                ) : (
                                  <span className="text-zinc-600 text-[10px]">—</span>
                                )}
                              </td>
                            </tr>
                          );
                        });
                        })()}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  !wifiLoading && <p className="text-xs text-zinc-600 py-2">No clients connected</p>
                )}
              </div>
            )}

            {/* Tab: Firewall Rules */}
            {wifiTab === "firewall" && (
              <div>
                <h4 className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">Firewall Rules {firewallRules.length > 0 ? `(${firewallRules.length})` : ""}</h4>
                {firewallRules.length > 0 ? (
                  <div className="overflow-x-auto rounded-lg border border-zinc-800">
                    <table className="w-full text-xs">
                      <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                        <th className="px-3 py-2 font-medium">Name</th>
                        <th className="px-3 py-2 font-medium">Action</th>
                        <th className="px-3 py-2 font-medium">Protocol</th>
                        <th className="px-3 py-2 font-medium">Source</th>
                        <th className="px-3 py-2 font-medium">Destination</th>
                        <th className="px-3 py-2 font-medium">Port</th>
                        <th className="px-3 py-2 font-medium">Status</th>
                        <th className="px-3 py-2 font-medium">Description</th>
                      </tr></thead>
                      <tbody>
                        {firewallRules.map((r: any) => (
                          <tr key={r.id} className="border-b border-zinc-800/50">
                            <td className="px-3 py-2 text-zinc-200">{r.name}</td>
                            <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${r.action === "allow" ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}`}>{r.action}</span></td>
                            <td className="px-3 py-2 text-zinc-400">{r.protocol}</td>
                            <td className="px-3 py-2 text-zinc-400 font-mono text-[10px]">{r.source_ip || "any"}{r.source_port ? `:${r.source_port}` : ""}</td>
                            <td className="px-3 py-2 text-zinc-400 font-mono text-[10px]">{r.dest_ip || "any"}</td>
                            <td className="px-3 py-2 text-zinc-400">{r.dest_port || "any"}</td>
                            <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${r.enabled ? "bg-green-500/10 text-green-400" : "bg-zinc-700/50 text-zinc-500"}`}>{r.enabled ? "Active" : "Disabled"}</span></td>
                            <td className="px-3 py-2 text-zinc-500 max-w-[150px] truncate">{r.description || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  !wifiLoading && <p className="text-xs text-zinc-600 py-2">No firewall rules</p>
                )}
              </div>
            )}

            {/* Tab: Port Forwards */}
            {wifiTab === "forwards" && (
              <div>
                <h4 className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">Port Forwards {portForwards.length > 0 ? `(${portForwards.length})` : ""}</h4>
                {portForwards.length > 0 ? (
                  <div className="overflow-x-auto rounded-lg border border-zinc-800">
                    <table className="w-full text-xs">
                      <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                        <th className="px-3 py-2 font-medium">Name</th>
                        <th className="px-3 py-2 font-medium">Protocol</th>
                        <th className="px-3 py-2 font-medium">Ext. Port</th>
                        <th className="px-3 py-2 font-medium">Int. IP</th>
                        <th className="px-3 py-2 font-medium">Int. Port</th>
                        <th className="px-3 py-2 font-medium">Status</th>
                        <th className="px-3 py-2 font-medium">Description</th>
                      </tr></thead>
                      <tbody>
                        {portForwards.map((f: any) => (
                          <tr key={f.id} className="border-b border-zinc-800/50">
                            <td className="px-3 py-2 text-zinc-200">{f.name}</td>
                            <td className="px-3 py-2 text-zinc-400">{f.protocol}</td>
                            <td className="px-3 py-2 text-zinc-400 font-mono">{f.external_port}</td>
                            <td className="px-3 py-2 text-zinc-400 font-mono">{f.internal_ip}</td>
                            <td className="px-3 py-2 text-zinc-400 font-mono">{f.internal_port}</td>
                            <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${f.enabled ? "bg-green-500/10 text-green-400" : "bg-zinc-700/50 text-zinc-500"}`}>{f.enabled ? "Active" : "Disabled"}</span></td>
                            <td className="px-3 py-2 text-zinc-500 max-w-[150px] truncate">{f.description || "—"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  !wifiLoading && <p className="text-xs text-zinc-600 py-2">No port forwards</p>
                )}
              </div>
            )}

            {/* Tab: MAC Filters */}
            {wifiTab === "macfilters" && (
              <div>
                <h4 className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">MAC Filters {macFilters.length > 0 ? `(${macFilters.length})` : ""}</h4>
                {macFilters.length > 0 ? (
                  <div className="overflow-x-auto rounded-lg border border-zinc-800">
                    <table className="w-full text-xs">
                      <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                        <th className="px-3 py-2 font-medium">Name</th>
                        <th className="px-3 py-2 font-medium">MAC</th>
                        <th className="px-3 py-2 font-medium">Action</th>
                        <th className="px-3 py-2 font-medium">Status</th>
                      </tr></thead>
                      <tbody>
                        {macFilters.map((f: any) => (
                          <tr key={f.id} className="border-b border-zinc-800/50">
                            <td className="px-3 py-2 text-zinc-200">{f.name || "?"}</td>
                            <td className="px-3 py-2 text-zinc-400 font-mono">{f.mac}</td>
                            <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${f.action === "allow" ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"}`}>{f.action}</span></td>
                            <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${f.enabled ? "bg-green-500/10 text-green-400" : "bg-zinc-700/50 text-zinc-500"}`}>{f.enabled ? "Active" : "Disabled"}</span></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  !wifiLoading && <p className="text-xs text-zinc-600 py-2">No MAC filters configured</p>
                )}
              </div>
            )}
          </div>
        )}
      </div>
      <ToastContainer toasts={toasts} />
    </div>
  );
}
