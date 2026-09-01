"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter, useSearchParams } from "next/navigation";

type Device = {
  id: string; hostname: string; vendor: string; model: string; serial: string; version: string
  category: string; device_type: string; ip: string; status: string
  cpu_usage: number; memory_usage: number; temperature: number
  uptime: string; last_seen: string; interface_errors: number; active_alerts: number
  location: string; description: string; connection_method: string; tags: string; health_score: number
};
type Interface = { id: number; device_id: string; name: string; status: string; vlan: string; speed: string; errors: number; drops: number; bandwidth_usage: number; description: string; mac: string; ip: string; port_security: boolean; bpdu_guard: boolean; stp_state: string; is_trunk: boolean };
type DashboardSummary = { health_score: number; total_devices: number; online_devices: number; warning_devices: number; critical_devices: number; offline_devices: number; active_ports: number; shutdown_ports: number; err_disabled_ports: number; flapping_ports: number; high_cpu_devices: number; high_memory_devices: number; security_events: number; active_alerts: number; failed_logins: number; unauthorized_macs: number; wifi_routers: number; total_wifi_clients: number };
type Action = { type: string; label: string; device?: string; interface?: string; client?: { mac: string; name?: string; band?: string }; command?: string };
type Message = { role: "user" | "ai"; text: string; actions?: Action[] };

const deviceCategories = [
  { label: "Core Switches", icon: "🔀" },
  { label: "Distribution Switches", icon: "🔀" },
  { label: "Access Switches", icon: "🔀" },
  { label: "Wireless Controllers", icon: "📶" },
  { label: "Access Points", icon: "📡" },
  { label: "Wireless Routers", icon: "📶" },
  { label: "Firewalls", icon: "🛡️" },
  { label: "Routers", icon: "🌐" },
  { label: "Servers", icon: "💻" },
];

const deviceTypes = ["Switch", "Router", "Firewall", "AP", "Controller", "Server", "Load Balancer", "WiFi Router", "Other"];
const vendors = ["Cisco", "Juniper", "Aruba", "Fortinet", "MikroTik", "Dell", "Huawei", "Palo Alto", "Arista", "Ubiquiti", "TP-Link", "Netgear", "Asus", "Linksys", "D-Link", "Other"];
const sshDeviceTypes = ["", "cisco_ios", "cisco_s300", "aruba_os", "junos", "linux", "generic"];

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

function StatCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
      <div className="text-xs text-zinc-500 uppercase tracking-wider">{label}</div>
      <div className={`mt-1 text-2xl font-bold ${color || "text-zinc-100"}`}>{value}</div>
    </div>
  );
}

function Input({ label, value, onChange, placeholder, type }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string; type?: string }) {
  return (
    <div>
      <label className="block text-xs text-zinc-400 mb-1">{label}</label>
      <input type={type || "text"} value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
        className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20" />
    </div>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: string[] }) {
  return (
    <div>
      <label className="block text-xs text-zinc-400 mb-1">{label}</label>
      <select value={value} onChange={e => onChange(e.target.value)}
        className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20">
        {options.map(o => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  );
}

function Checkbox({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-center gap-2 text-sm text-zinc-300 cursor-pointer">
      <input type="checkbox" checked={checked} onChange={e => onChange(e.target.checked)}
        className="rounded border-zinc-600 bg-zinc-800 text-blue-600 focus:ring-blue-500" />
      {label}
    </label>
  );
}

function ToastContainer({ toasts }: { toasts: {id: number; message: string; type: "online" | "offline"}[] }) {
  return (
    <div className="fixed top-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map(t => (
        <div key={t.id}
          className={`flex items-center gap-2 rounded-lg border px-4 py-3 text-sm font-medium shadow-lg animate-in slide-in-from-right ${
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

export default function Home() {
  const router = useRouter();
  const [view, setView] = useState<"dashboard" | "chat">("dashboard");
  const [showDevices, setShowDevices] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [dash, setDash] = useState<DashboardSummary | null>(null);
  const [wifiClients, setWifiClients] = useState<any[]>([]);
  const [wifiSettings, setWifiSettings] = useState<any>(null);
  const [wifiHealth, setWifiHealth] = useState<any>(null);
  const [wifiLoading, setWifiLoading] = useState(false);
  const [wifiError, setWifiError] = useState<string | null>(null);
  const [dhcpLeases, setDhcpLeases] = useState<any[]>([]);
  const [firewallRules, setFirewallRules] = useState<any[]>([]);
  const [portForwards, setPortForwards] = useState<any[]>([]);
  const [macFilters, setMacFilters] = useState<any[]>([]);
const [messages, setMessages] = useState<Message[]>([
    { role: "ai", text: "Hey there! I'm NetBot AI — your network operations assistant.\n\nI can help you monitor, troubleshoot, and automate your network. Here's what I can do:\n\n- Check device status\n- Troubleshoot interfaces\n- Tell you who's connected\n- Analyze Wi-Fi signal strength\n- Show bandwidth hogs\n- Look up devices on the network\n- Run commands on switches via SSH\n\nWhat's on your mind?" },
  ]);
  const [input, setInput] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showCredModal, setShowCredModal] = useState(false);
  const [showWifiWizard, setShowWifiWizard] = useState(false);
  const [showDeviceTypePicker, setShowDeviceTypePicker] = useState(false);
  const [showSwitchWizard, setShowSwitchWizard] = useState(false);
  const [formCred, setFormCred] = useState<{ deviceId: string; data: any } | null>(null);
  const [testResult, setTestResult] = useState<string | null>(null);
  const [discoveredInfo, setDiscoveredInfo] = useState<any>(null);
  const [testStatus, setTestStatus] = useState<"idle" | "testing" | "success" | "failed">("idle");
  const [testError, setTestError] = useState<string>("");
  const [scanSummary, setScanSummary] = useState<any>(null);
  const [scanHosts, setScanHosts] = useState<any[]>([]);
  const [scanLoading, setScanLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanHistory, setScanHistory] = useState<any[]>([]);
  const [toasts, setToasts] = useState<{id: number; message: string; type: "online" | "offline"}[]>([]);
  const prevStatusRef = useRef<Record<string, string>>({});
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

  const fetchDevices = () => apiFetch(`${API}/api/devices`).then(r => r.json()).then(setDevices).catch(() => {});
  const fetchDashboard = () => apiFetch(`${API}/api/dashboard/summary`).then(r => r.json()).then(setDash).catch(() => {});
  const fetchInterfaces = () => apiFetch(`${API}/api/interfaces`).then(r => r.json()).then(setInterfaces).catch(() => {});

  const fetchWifiData = async (deviceId: string) => {
    setWifiLoading(true);
    setWifiError(null);
    const errors: string[] = [];
    try {
      const [clientsRes, settingsRes, healthRes, dhcpRes, fwRes, pfRes, mfRes] = await Promise.all([
        apiFetch(`${API}/api/wifi/${deviceId}/clients`),
        apiFetch(`${API}/api/wifi/${deviceId}/settings`),
        apiFetch(`${API}/api/wifi/${deviceId}/health`),
        apiFetch(`${API}/api/wifi/${deviceId}/dhcp-leases`),
        apiFetch(`${API}/api/wifi/${deviceId}/firewall-rules`),
        apiFetch(`${API}/api/wifi/${deviceId}/port-forwards`),
        apiFetch(`${API}/api/wifi/${deviceId}/mac-filters`),
      ]);
      if (clientsRes.ok) { const d = await clientsRes.json(); setWifiClients(Array.isArray(d) ? d : []); }
      else errors.push(`Clients: ${clientsRes.status}`);
      if (settingsRes.ok) { const d = await settingsRes.json(); setWifiSettings(d); }
      else if (settingsRes.status !== 404) errors.push(`Settings: ${settingsRes.status}`);
      if (healthRes.ok) { const d = await healthRes.json(); setWifiHealth(d); }
      else if (healthRes.status !== 404) errors.push(`Health: ${healthRes.status}`);
      if (dhcpRes.ok) { const d = await dhcpRes.json(); setDhcpLeases(Array.isArray(d) ? d : []); }
      if (fwRes.ok) { const d = await fwRes.json(); setFirewallRules(Array.isArray(d) ? d : []); }
      if (pfRes.ok) { const d = await pfRes.json(); setPortForwards(Array.isArray(d) ? d : []); }
      if (mfRes.ok) { const d = await mfRes.json(); setMacFilters(Array.isArray(d) ? d : []); }
    } catch { errors.push("Network error"); }
    if (errors.length) setWifiError("Failed to load: " + errors.join(", "));
    setWifiLoading(false);
  };

  const searchParams = useSearchParams();

  useEffect(() => {
    Promise.all([fetchDevices(), fetchDashboard(), fetchInterfaces(), fetchScanSummary(), fetchScanHistory()]).then(() => {
      setLoading(false);
      // Initialize prevStatusRef with current device statuses
      apiFetch(`${API}/api/devices`).then(r => r.json()).then((ds: Device[]) => {
        const map: Record<string, string> = {};
        ds.forEach(d => { map[d.id] = d.status; });
        prevStatusRef.current = map;
      }).catch(() => {});
    });
  }, []);

  useEffect(() => {
    if (!devices.length) return;
    const chatParam = searchParams?.get("chat");
    const deviceParam = searchParams?.get("device");
    if (chatParam === "1" && deviceParam) {
      const dev = devices.find(d => d.id === deviceParam);
      if (dev) {
        setSelectedDevice(dev);
        setView("chat");
      }
    }
  }, [devices, searchParams]);

  // Poll device status every 10s and notify on changes
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const res = await apiFetch(`${API}/api/devices`);
        const current: Device[] = await res.json();
        setDevices(current);
        current.forEach(d => {
          const prev = prevStatusRef.current[d.id];
          if (prev && prev !== d.status && (d.status === "online" || d.status === "offline")) {
            addToast(`${d.hostname} is now ${d.status}`, d.status as "online" | "offline");
          }
          prevStatusRef.current[d.id] = d.status;
        });
      } catch {}
    }, 10000);
    return () => clearInterval(interval);
  }, []);

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

  useEffect(() => {
    if (selectedDevice?.device_type === "WiFi Router") {
      fetchWifiData(selectedDevice.id);
    } else {
      setWifiClients([]);
      setWifiSettings(null);
      setWifiHealth(null);
      setDhcpLeases([]); setFirewallRules([]); setPortForwards([]); setMacFilters([]);
      setWifiError(null);
      setWifiLoading(false);
    }
  }, [selectedDevice]);

  const grouped = deviceCategories.map((dc) => ({
    ...dc, devices: devices.filter((d) => d.category === dc.label),
  }));

  const fetchScanSummary = () => {
    apiFetch(`${API}/api/network/summary`).then(r => r.json()).then(d => { setScanSummary(d); setScanHosts([]); }).catch(() => {});
  };
  const fetchScanHistory = () => {
    apiFetch(`${API}/api/network/scans?limit=5`).then(r => r.json()).then(setScanHistory).catch(() => {});
  };

  const handleScanNetwork = async () => {
    setScanning(true);
    setScanHosts([]);
    try {
      const res = await apiFetch(`${API}/api/network/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ router_id: "", network: "", scan_type: "manual" }),
      });
      const data = await res.json();
      setScanHosts(data.hosts || []);
      await fetchScanSummary();
      await fetchScanHistory();
    } catch (e) { /* ignore */ }
    setScanning(false);
  };

  const handleDeviceClick = async (device: Device) => {
    router.push(`/device/${device.id}`);
  };

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isThinking]);

  const handleSend = async () => {
    if (!input.trim() || isThinking) return;
    const msg = input; setInput("");
    setMessages((prev) => [...prev, { role: "user", text: msg }]);
    setIsThinking(true);
    try {
      const history = messages.map((m) => ({ role: m.role === "ai" ? "assistant" : "user", content: m.text }));
      const res = await apiFetch(`${API}/api/chat`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: msg, device_id: selectedDevice?.id, history }),
      });
      const data = await res.json();
      setMessages((prev) => [...prev, { role: "ai", text: data.reply, actions: data.actions || [] }]);
    } catch { setMessages((prev) => [...prev, { role: "ai", text: "Hmm, something went wrong. Can you try again?" }]); }
    setIsThinking(false);
  };

  const executeAction = async (action: Action) => {
    if (action.type === "block_wifi_client" && action.client) {
      if (!window.confirm(`Block ${action.client.mac}?`)) return;
      try {
        await apiFetch(`${API}/api/wifi/${selectedDevice?.id || "192-168-0-1"}/block-client`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mac: action.client.mac, name: action.client.name || "", band: action.client.band || "" }),
        });
      } catch {}
    } else if (action.type === "unblock_wifi_client" && action.client) {
      if (!window.confirm(`Unblock ${action.client.mac}?`)) return;
      try {
        await apiFetch(`${API}/api/wifi/${selectedDevice?.id || "192-168-0-1"}/unblock-client`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mac: action.client.mac, band: action.client.band || "" }),
        });
      } catch {}
    }
  };

  // --- Add Device Form ---
  const [addForm, setAddForm] = useState({
    id: "", hostname: "", vendor: "Cisco", model: "", serial: "", version: "",
    category: "Access Switches", device_type: "Switch", ip: "",
    location: "", description: "", connection_method: "SSH", tags: "",
  });
  const resetAddForm = () => setAddForm({
    id: "", hostname: "", vendor: "Cisco", model: "", serial: "", version: "",
    category: "Access Switches", device_type: "Switch", ip: "",
    location: "", description: "", connection_method: "SSH", tags: "",
  });

  const handleAddDevice = async () => {
    try {
      const res = await apiFetch(`${API}/api/devices`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(addForm),
      });
      if (!res.ok) { const err = await res.json(); alert(err.detail || "Failed to create device"); return; }
      const device = await res.json();
      setShowAddModal(false);
      resetAddForm();
      await fetchDevices();
      setFormCred({ deviceId: device.id, data: {} });
      setShowCredModal(true);
    } catch (e) { alert("Failed to create device"); }
  };

  // --- WiFi Add Form ---
  const [wifiForm, setWifiForm] = useState({
    hostname: "", mgmt_ip: "", username: "", password: "", mgmt_protocol: "HTTPS",
  });
  const resetWifiForm = () => {
    setWifiForm({ hostname: "", mgmt_ip: "", username: "", password: "", mgmt_protocol: "HTTPS" });
    setDiscoveredInfo(null);
    setTestStatus("idle");
    setTestError("");
    setWifiError(null);
  };

  const [switchForm, setSwitchForm] = useState({
    ip: "", port: 22, username: "", password: "", enable_secret: "", hostname: "", device_type: "",
  });
  const [switchTestStatus, setSwitchTestStatus] = useState<"idle" | "testing" | "success" | "failed">("idle");
  const [switchDiscoveredInfo, setSwitchDiscoveredInfo] = useState<any>(null);
  const [switchTestError, setSwitchTestError] = useState("");

  const resetSwitchForm = () => {
    setSwitchForm({ ip: "", port: 22, username: "", password: "", enable_secret: "", hostname: "", device_type: "" });
    setSwitchDiscoveredInfo(null);
    setSwitchTestStatus("idle");
    setSwitchTestError("");
  };

  const handleTestWifiConnection = async () => {
    setTestStatus("testing");
    setTestError("");
    const cleanAddr = wifiForm.mgmt_ip.replace(/^https?:\/\//i, "").split("/")[0].split("?")[0];
    try {
      const res = await apiFetch(`${API}/api/wifi/test-connection`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hostname: wifiForm.hostname,
          mgmt_ip: cleanAddr, mgmt_protocol: wifiForm.mgmt_protocol,
          username: wifiForm.username, password: wifiForm.password,
        }),
      });
      const data = await res.json();
      if (!data.success) {
        setTestStatus("failed");
        setTestError(data.error || "Connection failed");
        return;
      }
      setDiscoveredInfo(data);
      setTestStatus("success");
    } catch {
      setTestStatus("failed");
      setTestError("Unable to reach the backend. Check that the server is running.");
    }
  };

  const handleSaveWifiRouter = async () => {
    try {
      const info = discoveredInfo || {};
      const cleanAddr = info.mgmt_address || wifiForm.mgmt_ip.replace(/^https?:\/\//i, "").split("/")[0].split("?")[0];
      const deviceId = cleanAddr.replace(/\./g, "-") || wifiForm.hostname.toLowerCase().replace(/[^a-z0-9-]/g, "-");
      const devRes = await apiFetch(`${API}/api/devices`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: deviceId,
          hostname: info.hostname || wifiForm.hostname,
          vendor: info.vendor || "Other", model: info.model || "",
          serial: info.serial || "", version: info.firmware || "",
          category: "Wireless Routers", device_type: "WiFi Router",
          ip: cleanAddr, location: "", description: "",
          connection_method: wifiForm.mgmt_protocol, tags: "wifi,wireless",
          uptime: info.uptime || "", status: "online",
        }),
      });
      if (!devRes.ok) { try { const err = await devRes.json(); alert(err.detail || "Failed to create router"); } catch { alert("Failed to create router (" + devRes.status + ")"); } return; }
      const device = await devRes.json();

      if (wifiForm.username || wifiForm.password) {
        await apiFetch(`${API}/api/devices/${device.id}/credentials`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: wifiForm.username, password: wifiForm.password }),
        });
      }

      // Sync all router data (settings, clients, DHCP leases)
      await apiFetch(`${API}/api/wifi/${device.id}/sync`, { method: "POST" });

      setShowWifiWizard(false);
      resetWifiForm();
      await fetchDevices();
    } catch (e) { alert("Failed to save WiFi router: " + (e instanceof Error ? e.message : e)); }
  };

  const handleTestSwitchConnection = async () => {
    setSwitchTestStatus("testing");
    setSwitchTestError("");
    try {
      const res = await apiFetch(`${API}/api/devices/test-ssh`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(switchForm),
      });
      const data = await res.json();
      if (!data.success) {
        setSwitchTestStatus("failed");
        setSwitchTestError(data.error || "Connection failed");
        return;
      }
      setSwitchDiscoveredInfo(data);
      setSwitchTestStatus("success");
    } catch {
      setSwitchTestStatus("failed");
      setSwitchTestError("Unable to reach the backend. Check that the server is running.");
    }
  };

  const handleSaveSwitch = async () => {
    try {
      const info = switchDiscoveredInfo || {};
      const deviceId = (info.hostname || switchForm.hostname || switchForm.ip).toLowerCase().replace(/[^a-z0-9-]/g, "-") || switchForm.ip.replace(/\./g, "-");
      const devRes = await apiFetch(`${API}/api/devices`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: deviceId,
          hostname: info.hostname || switchForm.hostname || switchForm.ip,
          vendor: info.vendor || "Other", model: info.model || "",
          serial: info.serial || "", version: info.version || "",
          category: "Access Switches", device_type: "Switch",
          ip: switchForm.ip, location: "", description: "",
          connection_method: "SSH", tags: "switch,network",
          uptime: info.uptime || "", status: "online",
        }),
      });
      if (!devRes.ok) { try { const err = await devRes.json(); alert(err.detail || "Failed to create switch"); } catch { alert("Failed to create switch (" + devRes.status + ")"); } return; }
      const device = await devRes.json();

      if (switchForm.username || switchForm.password) {
        await apiFetch(`${API}/api/devices/${device.id}/credentials`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            username: switchForm.username, password: switchForm.password,
            ssh_port: switchForm.port, enable_secret: switchForm.enable_secret,
            auth_type: "password",
          }),
        });
      }

      setShowSwitchWizard(false);
      resetSwitchForm();
      await fetchDevices();
    } catch (e) { alert("Failed to save switch: " + (e instanceof Error ? e.message : e)); }
  };

  const [credForm, setCredForm] = useState({
    username: "", password: "", enable_secret: "", ssh_port: 22, auth_type: "password",
    ssh_key: "", passphrase: "",
    snmp_version: "v2c", snmp_community: "public",
    snmp_v3_username: "", snmp_auth_protocol: "SHA", snmp_auth_password: "",
    snmp_privacy_protocol: "AES", snmp_privacy_password: "",
    api_base_url: "", api_token: "", api_username: "", api_password: "",
  });

  const handleSaveCredentials = async () => {
    if (!formCred) return;
    try {
      const res = await apiFetch(`${API}/api/devices/${formCred.deviceId}/credentials`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(credForm),
      });
      if (!res.ok) { const err = await res.json(); alert(err.detail || "Failed to save credentials"); return; }
      setShowCredModal(false);
      setFormCred(null);
    } catch { alert("Failed to save credentials"); }
  };

  const handleTestConnection = async () => {
    if (!formCred) return;
    setTestResult("Testing...");
    try {
      const res = await apiFetch(`${API}/api/devices/${formCred.deviceId}/test-connection`, { method: "POST" });
      const data = await res.json();
      setTestResult(data.message);
    } catch { setTestResult("Connection test failed"); }
  };

  return (
    <div className="flex h-screen flex-col bg-zinc-950 text-zinc-100 font-sans">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-zinc-800 px-6 py-3">
        <div className="flex items-center gap-3">
          <span className="text-2xl">🤖</span>
          <h1 className="text-lg font-semibold tracking-tight">NetBot AI</h1>
          <div className="ml-4 flex gap-1 rounded-lg bg-zinc-900 p-0.5">
            <button onClick={() => setView("dashboard")} className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${view === "dashboard" ? "bg-blue-600 text-white" : "text-zinc-400 hover:text-zinc-300"}`}>Dashboard</button>
            <button onClick={() => setView("chat")} className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${view === "chat" ? "bg-blue-600 text-white" : "text-zinc-400 hover:text-zinc-300"}`}>Chat</button>
          </div>
        </div>
        <div className="flex items-center gap-3 text-sm text-zinc-400">
          <button onClick={() => { setShowDeviceTypePicker(true); }}
            className="flex items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500 transition-colors">
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" /></svg>
            Add Device
          </button>
          <span className={`inline-block h-2 w-2 rounded-full ${loading ? "bg-yellow-500" : "bg-green-500"}`} />
          {loading ? "Connecting..." : `${devices.length} devices`}
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        {/* Device Sidebar */}
        <aside className={`${showDevices ? "w-80" : "w-0"} flex-shrink-0 border-r border-zinc-800 bg-zinc-900/50 transition-all duration-300 overflow-hidden`}>
          <div className="flex h-full flex-col">
            <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
              <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider">Device Inventory</h2>
              <button onClick={() => setShowDevices(false)} className="text-zinc-500 hover:text-zinc-300 text-lg leading-none">&times;</button>
            </div>
            <div className="flex-1 overflow-y-auto p-3 space-y-4">
              {grouped.map((group) => group.devices.length > 0 && (
                <div key={group.label}>
                  <div className="flex items-center gap-2 text-xs font-medium text-zinc-500 uppercase tracking-wider mb-2 px-1">
                    <span>{group.icon}</span><span>{group.label}</span>
                    <span className="text-zinc-700">({group.devices.length})</span>
                  </div>
                  <div className="space-y-1">
                    {group.devices.map((d) => (
                      <div key={d.id} className="group relative">
                        <button onClick={() => handleDeviceClick(d)} className={`w-full rounded-lg px-3 py-2 text-left text-sm transition-colors ${selectedDevice?.id === d.id ? "bg-blue-600/20 text-blue-400 ring-1 ring-blue-500/30" : "text-zinc-300 hover:bg-zinc-800"}`}>
                          <div className="flex items-center gap-3">
                            <span className={`inline-block h-2 w-2 flex-shrink-0 rounded-full ${statusColor(d.status)}`} />
                            <div className="flex-1 min-w-0">
                              <div className="truncate font-medium">{d.hostname}</div>
                              <div className="flex items-center gap-2 text-xs text-zinc-500">
                                <span>{d.vendor}</span>
                                <span>•</span>
                                <span>{d.ip}</span>
                              </div>
                            </div>
                            <a href={`/device/${d.id}`} onClick={e => e.stopPropagation()} className="shrink-0 rounded p-1 text-zinc-600 opacity-0 group-hover:opacity-100 hover:text-zinc-300 hover:bg-zinc-800 transition-all" title="View Details">
                              <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                            </a>
                          </div>
                          <div className="mt-1.5 flex items-center gap-3 text-xs text-zinc-600">
                            <span className="flex items-center gap-1">
                              <span className={`inline-block h-1.5 w-1.5 rounded-full ${d.cpu_usage > 80 ? "bg-red-500" : d.cpu_usage > 60 ? "bg-yellow-500" : "bg-green-500"}`} />
                              CPU {d.cpu_usage}%
                            </span>
                            <span>MEM {d.memory_usage}%</span>
                            <span>{d.last_seen}</span>
                          </div>
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* Main Content */}
        <div className="flex flex-1 flex-col overflow-hidden">
          {!showDevices && view !== "dashboard" && (
            <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-2">
              <button onClick={() => setShowDevices(true)} className="flex items-center gap-2 rounded-lg bg-zinc-800 px-4 py-1.5 text-sm text-zinc-300 hover:bg-zinc-700 transition-colors">
                <span className="text-base">📋</span> Device Inventory
              </button>
              {selectedDevice && (
                <span className="text-sm text-zinc-500">Connected: <span className="text-zinc-300">{selectedDevice.hostname}</span></span>
              )}
            </div>
          )}

          <div className="flex-1 overflow-y-auto">
            {view === "dashboard" ? (
              <div className="p-6 space-y-6">
                {/* Health Score */}
                {dash && (
                  <div className="flex items-center gap-6">
                    <div className="flex flex-col items-center justify-center rounded-2xl border border-zinc-800 bg-zinc-900/60 p-6 w-48">
                      <div className="text-5xl font-bold text-blue-400">{dash.health_score}</div>
                      <div className="mt-1 text-sm text-zinc-400">/100</div>
                      <div className="mt-1 text-xs text-zinc-500">Network Health</div>
                    </div>
                    <div className="flex-1 grid grid-cols-2 lg:grid-cols-4 gap-3">
                      <StatCard label="Online" value={dash.online_devices} color="text-green-400" />
                      <StatCard label="Warning" value={dash.warning_devices} color="text-yellow-400" />
                      <StatCard label="Critical" value={dash.critical_devices} color="text-red-400" />
                      <StatCard label="Offline" value={dash.offline_devices} color="text-zinc-400" />
                    </div>
                  </div>
                )}

                {/* Summary Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                    <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Port Summary</h3>
                    {dash && (
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between"><span className="text-zinc-400">Active</span><span className="text-green-400">{dash.active_ports}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">Shutdown</span><span className="text-zinc-400">{dash.shutdown_ports}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">Err-Disabled</span><span className="text-orange-400">{dash.err_disabled_ports}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">Flapping</span><span className="text-yellow-400">{dash.flapping_ports}</span></div>
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                    <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Wi-Fi Overview</h3>
                    {dash && (
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between"><span className="text-zinc-400">Wi-Fi Routers</span><span className="text-emerald-400">{dash.wifi_routers}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">Connected Clients</span><span className="text-blue-400">{dash.total_wifi_clients}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">Security Events</span><span className={dash.security_events > 0 ? "text-red-400" : "text-green-400"}>{dash.security_events}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">Active Alerts</span><span className="text-red-400">{dash.active_alerts}</span></div>
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                    <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Performance</h3>
                    {dash && (
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between"><span className="text-zinc-400">High CPU Devices</span><span className={dash.high_cpu_devices > 0 ? "text-red-400" : "text-green-400"}>{dash.high_cpu_devices}</span></div>
                        <div className="flex justify-between"><span className="text-zinc-400">High Memory</span><span className={dash.high_memory_devices > 0 ? "text-red-400" : "text-green-400"}>{dash.high_memory_devices}</span></div>
                      </div>
                    )}
                    <div className="mt-3">
                      <h4 className="text-xs text-zinc-500 mb-1">Bandwidth Hotspots</h4>
                      {interfaces.filter(i => i.bandwidth_usage > 50).slice(0, 2).map(i => (
                        <div key={i.id} className="flex justify-between text-xs"><span className="text-zinc-400 truncate">{i.name} ({i.device_id})</span><span className="text-yellow-400">{i.bandwidth_usage}%</span></div>
                      ))}
                      {interfaces.filter(i => i.bandwidth_usage > 50).length === 0 && <div className="text-xs text-zinc-600">None detected</div>}
                    </div>
                  </div>
                  <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4">
                    <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-3">Devices by Vendor</h3>
                    <div className="space-y-2 text-sm">
                      {[...new Set(devices.map(d => d.vendor))].map(v => (
                        <div key={v} className="flex justify-between"><span className="text-zinc-400">{v}</span><span className="text-zinc-300">{devices.filter(d => d.vendor === v).length}</span></div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Device List */}
                <div>
                  <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">All Devices</h2>
                  <div className="overflow-x-auto rounded-xl border border-zinc-800">
                    <table className="w-full text-sm">
                      <thead><tr className="border-b border-zinc-800 text-left text-xs text-zinc-500">
                        <th className="px-4 py-3 font-medium">Hostname</th>
                        <th className="px-4 py-3 font-medium">Vendor</th>
                        <th className="px-4 py-3 font-medium">IP</th>
                        <th className="px-4 py-3 font-medium">Status</th>
                        <th className="px-4 py-3 font-medium">CPU</th>
                        <th className="px-4 py-3 font-medium">Memory</th>
                        <th className="px-4 py-3 font-medium">Category</th>
                      </tr></thead>
                      <tbody>
                        {devices.map(d => (
                          <tr key={d.id} className="border-b border-zinc-800/50 hover:bg-zinc-900/50 cursor-pointer group" onClick={() => handleDeviceClick(d)}>
                            <td className="px-4 py-3 font-medium text-zinc-200">
                              <div className="flex items-center gap-2">
                                <span>{d.hostname}</span>
                                <a href={`/device/${d.id}`} onClick={e => e.stopPropagation()} className="shrink-0 rounded p-0.5 text-zinc-700 opacity-0 group-hover:opacity-100 hover:text-zinc-300 hover:bg-zinc-800 transition-all" title="View Details">
                                  <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" /></svg>
                                </a>
                              </div>
                            </td>
                            <td className="px-4 py-3 text-zinc-400">{d.vendor}</td>
                            <td className="px-4 py-3 text-zinc-400 font-mono text-xs">{d.ip}</td>
                            <td className="px-4 py-3"><span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${d.status === "online" ? "text-green-400 bg-green-500/10" : d.status === "warning" ? "text-yellow-400 bg-yellow-500/10" : d.status === "critical" ? "text-red-400 bg-red-500/10" : "text-zinc-400 bg-zinc-500/10"}`}><span className={`inline-block h-1.5 w-1.5 rounded-full ${statusColor(d.status)}`} />{d.status}</span></td>
                            <td className="px-4 py-3"><div className="flex items-center gap-2"><div className="h-1.5 w-16 rounded-full bg-zinc-800"><div className={`h-full rounded-full ${d.cpu_usage > 80 ? "bg-red-500" : d.cpu_usage > 60 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${d.cpu_usage}%` }} /></div><span className="text-xs text-zinc-500">{d.cpu_usage}%</span></div></td>
                            <td className="px-4 py-3"><div className="flex items-center gap-2"><div className="h-1.5 w-16 rounded-full bg-zinc-800"><div className={`h-full rounded-full ${d.memory_usage > 80 ? "bg-red-500" : d.memory_usage > 60 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${d.memory_usage}%` }} /></div><span className="text-xs text-zinc-500">{d.memory_usage}%</span></div></td>
                            <td className="px-4 py-3 text-zinc-500 text-xs">{d.category}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Network Scan Section */}
                <div className="border-t border-zinc-800 pt-6 mt-6">
                  <div className="flex items-center justify-between mb-4">
                    <h2 className="text-sm font-medium text-zinc-400 uppercase tracking-wider">Network Scan</h2>
                    <button onClick={handleScanNetwork} disabled={scanning}
                      className="flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-xs font-medium text-white hover:bg-emerald-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                      {scanning ? (
                        <><div className="animate-spin inline-block h-3 w-3 border-2 border-white border-t-transparent rounded-full" /> Scanning...</>
                      ) : (
                        <><svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" /></svg> Scan Network</>
                      )}
                    </button>
                  </div>

                  {/* Scan Summary Card */}
                  {scanSummary && scanSummary.last_scan && (
                    <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 mb-4">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider">Last Scan</h3>
                        <span className="text-xs text-zinc-500">Network: {scanSummary.last_scan.network || "—"}</span>
                      </div>
                      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs">
                        <div className="rounded-lg bg-zinc-800/50 p-2"><span className="text-zinc-500">Devices Found</span><div className="font-medium text-zinc-200">{scanSummary.last_scan.hosts_found}</div></div>
                        <div className="rounded-lg bg-zinc-800/50 p-2"><span className="text-zinc-500">Online</span><div className="font-medium text-green-400">{scanSummary.hosts_online ?? scanSummary.last_scan.hosts_found}</div></div>
                        <div className="rounded-lg bg-zinc-800/50 p-2"><span className="text-zinc-500">Duration</span><div className="font-medium text-zinc-200">{scanSummary.last_scan.duration_sec}s</div></div>
                        <div className="rounded-lg bg-zinc-800/50 p-2"><span className="text-zinc-500">New Devices</span><div className={`font-medium ${scanSummary.new_devices > 0 ? "text-yellow-400" : "text-green-400"}`}>{scanSummary.new_devices}</div></div>
                        <div className="rounded-lg bg-zinc-800/50 p-2"><span className="text-zinc-500">Anomalies</span><div className={`font-medium ${scanSummary.anomalies > 0 ? "text-red-400" : "text-green-400"}`}>{scanSummary.anomalies}</div></div>
                      </div>
                    </div>
                  )}

                  {/* Scan History */}
                  {scanHistory.length > 0 && (
                    <div className="overflow-x-auto rounded-xl border border-zinc-800 mb-4">
                      <table className="w-full text-xs">
                        <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                          <th className="px-3 py-2 font-medium">Network</th>
                          <th className="px-3 py-2 font-medium">Type</th>
                          <th className="px-3 py-2 font-medium">Found</th>
                          <th className="px-3 py-2 font-medium">Online</th>
                          <th className="px-3 py-2 font-medium">New</th>
                          <th className="px-3 py-2 font-medium">Anomalies</th>
                          <th className="px-3 py-2 font-medium">Duration</th>
                          <th className="px-3 py-2 font-medium">Completed</th>
                        </tr></thead>
                        <tbody>
                          {scanHistory.map((s: any) => (
                            <tr key={s.id} className="border-b border-zinc-800/50">
                              <td className="px-3 py-2 text-zinc-200 font-mono">{s.network}</td>
                              <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${s.scan_type === "scheduled" ? "bg-blue-500/10 text-blue-400" : "bg-emerald-500/10 text-emerald-400"}`}>{s.scan_type}</span></td>
                              <td className="px-3 py-2 text-zinc-300">{s.hosts_found}</td>
                              <td className="px-3 py-2 text-green-400">{s.hosts_online}</td>
                              <td className={`px-3 py-2 ${s.new_devices > 0 ? "text-yellow-400" : "text-zinc-500"}`}>{s.new_devices}</td>
                              <td className={`px-3 py-2 ${s.anomalies > 0 ? "text-red-400" : "text-zinc-500"}`}>{s.anomalies}</td>
                              <td className="px-3 py-2 text-zinc-500">{s.duration_sec}s</td>
                              <td className="px-3 py-2 text-zinc-500">{s.completed_at?.slice(0, 19).replace("T", " ") || "—"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}

                  {/* Discovered Devices Table */}
                  {scanHosts.length > 0 && (
                    <div>
                      <h3 className="text-xs font-medium text-zinc-500 uppercase tracking-wider mb-2">Discovered Devices ({scanHosts.length})</h3>
                      <div className="overflow-x-auto rounded-xl border border-zinc-800">
                        <table className="w-full text-xs">
                          <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                            <th className="px-3 py-2 font-medium">Hostname</th>
                            <th className="px-3 py-2 font-medium">IP</th>
                            <th className="px-3 py-2 font-medium">MAC</th>
                            <th className="px-3 py-2 font-medium">Vendor</th>
                            <th className="px-3 py-2 font-medium">Status</th>
                            <th className="px-3 py-2 font-medium">Response</th>
                            <th className="px-3 py-2 font-medium">First Seen</th>
                            <th className="px-3 py-2 font-medium">Flags</th>
                            <th className="px-3 py-2 font-medium">Actions</th>
                          </tr></thead>
                          <tbody>
                            {scanHosts.slice(0, 50).map((h: any) => (
                              <tr key={h.id || h.ip} className="border-b border-zinc-800/50 hover:bg-zinc-900/50">
                                <td className="px-3 py-2 text-zinc-200 font-medium">{h.hostname || "?"}</td>
                                <td className="px-3 py-2 text-zinc-400 font-mono">{h.ip}</td>
                                <td className="px-3 py-2 text-zinc-500 font-mono">{h.mac || "—"}</td>
                                <td className="px-3 py-2 text-zinc-400">{h.vendor || "?"}</td>
                                <td className="px-3 py-2"><span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${h.status === "online" ? "text-green-400 bg-green-500/10" : "text-red-400 bg-red-500/10"}`}><span className={`inline-block h-1.5 w-1.5 rounded-full ${h.status === "online" ? "bg-green-500" : "bg-red-500"}`} />{h.status}</span></td>
                                <td className="px-3 py-2 text-zinc-500">{h.response_time}ms</td>
                                <td className="px-3 py-2 text-zinc-500">{h.first_seen?.slice(0, 19).replace("T", " ") || "—"}</td>
                                <td className="px-3 py-2">
                                  <div className="flex gap-1">
                                    {h.is_new && <span className="rounded bg-yellow-500/10 px-1 py-0.5 text-yellow-400 text-[10px] font-medium">NEW</span>}
                                    {h.is_duplicate_ip && <span className="rounded bg-red-500/10 px-1 py-0.5 text-red-400 text-[10px] font-medium">DUP IP</span>}
                                    {h.is_duplicate_mac && <span className="rounded bg-red-500/10 px-1 py-0.5 text-red-400 text-[10px] font-medium">DUP MAC</span>}
                                  </div>
                                </td>
                                <td className="px-3 py-2">
                                  <a href={`/device/${h.ip.replace(/\./g, "-")}`} className="rounded bg-zinc-800 px-2 py-1 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-700 transition-colors text-[10px]">
                                    View
                                  </a>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex justify-center mt-6">
                  <button onClick={() => setView("chat")} className="rounded-xl bg-blue-600 px-6 py-3 text-sm font-medium text-white hover:bg-blue-500 transition-colors">
                    Open AI Chat Assistant
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex h-full flex-col">
                {/* Device Detail Bar */}
                {selectedDevice && (
                  <div className="border-b border-zinc-800 bg-zinc-900/30 px-4 py-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <span className={`inline-block h-2.5 w-2.5 rounded-full ${statusColor(selectedDevice.status)}`} />
                        <div>
                          <div className="font-medium text-zinc-200">{selectedDevice.hostname}</div>
                          <div className="text-xs text-zinc-500">{selectedDevice.vendor} {selectedDevice.model} • {selectedDevice.ip}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-zinc-500">
                        <span>CPU: {selectedDevice.cpu_usage}%</span>
                        <span>MEM: {selectedDevice.memory_usage}%</span>
                        <span>Temp: {selectedDevice.temperature}°C</span>
                        <span>Uptime: {selectedDevice.uptime}</span>
                        {selectedDevice.device_type === "WiFi Router" && wifiHealth && (
                          <>
                            <span className="text-emerald-400">Clients: {wifiHealth.connected_clients}</span>
                            <span className="text-blue-400">Health: {wifiHealth.health_score}/100</span>
                          </>
                        )}
                      </div>
                    </div>
                    {/* Quick Actions */}
                    <div className="mt-2 flex gap-2">
                      <button className="rounded-lg bg-blue-600/10 px-3 py-1 text-xs text-blue-400 hover:bg-blue-600/20">Connect</button>
                      <button className="rounded-lg bg-zinc-800 px-3 py-1 text-xs text-zinc-400 hover:bg-zinc-700">Backup Config</button>
                      <button className="rounded-lg bg-zinc-800 px-3 py-1 text-xs text-zinc-400 hover:bg-zinc-700">Run Diagnostics</button>
                      <button className="rounded-lg bg-zinc-800 px-3 py-1 text-xs text-zinc-400 hover:bg-zinc-700">Show Logs</button>
                      <button className="rounded-lg bg-zinc-800 px-3 py-1 text-xs text-zinc-400 hover:bg-zinc-700">Compliance Check</button>
                    </div>
                    {/* WiFi Router Detail */}
                    {selectedDevice.device_type === "WiFi Router" && (
                      <div className="mt-3">
                        {wifiLoading && (
                          <div className="flex items-center gap-2 text-xs text-zinc-500 py-2">
                            <div className="animate-spin inline-block h-3 w-3 border-2 border-emerald-500 border-t-transparent rounded-full" />
                            Loading WiFi data...
                          </div>
                        )}
                        {wifiError && (
                          <div className="rounded-lg border border-red-800 bg-red-900/20 p-2 mb-2">
                            <p className="text-xs text-red-400">{wifiError}</p>
                          </div>
                        )}
                        {wifiSettings && (
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs mb-3">
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">Internet</span>
                              <div className={`font-medium ${wifiSettings.internet_status === "online" ? "text-green-400" : "text-red-400"}`}>{wifiSettings.internet_status}</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">WAN IP</span>
                              <div className="font-medium text-zinc-200 font-mono">{wifiSettings.wan_ip || "—"}</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">2.4GHz SSID</span>
                              <div className="font-medium text-zinc-200">{wifiSettings.ssid_24 || "—"} {wifiSettings.enabled_24 ? "" : "(disabled)"}</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">5GHz SSID</span>
                              <div className="font-medium text-zinc-200">{wifiSettings.ssid_5 || "—"} {wifiSettings.enabled_5 ? "" : "(disabled)"}</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">WAN Throughput</span>
                              <div className="font-medium text-zinc-200">{wifiSettings.wan_throughput} Mbps</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">LAN Throughput</span>
                              <div className="font-medium text-zinc-200">{wifiSettings.lan_throughput} Mbps</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">2.4GHz Clients</span>
                              <div className="font-medium text-zinc-200">{wifiSettings.clients_24}</div>
                            </div>
                            <div className="rounded-lg bg-zinc-800/50 p-2">
                              <span className="text-zinc-500">5GHz Clients</span>
                              <div className="font-medium text-zinc-200">{wifiSettings.clients_5}</div>
                            </div>
                          </div>
                        )}
                        {/* Summary Counts */}
                        {(dhcpLeases.length > 0 || firewallRules.length > 0 || portForwards.length > 0) && (
                          <div className="flex gap-2 mb-3 text-[10px]">
                            {dhcpLeases.length > 0 && <span className="rounded-lg bg-blue-500/10 px-2 py-1 text-blue-400">{dhcpLeases.length} DHCP Leases</span>}
                            {firewallRules.length > 0 && <span className="rounded-lg bg-amber-500/10 px-2 py-1 text-amber-400">{firewallRules.length} Firewall Rules</span>}
                            {portForwards.length > 0 && <span className="rounded-lg bg-purple-500/10 px-2 py-1 text-purple-400">{portForwards.length} Port Forwards</span>}
                            {macFilters.length > 0 && <span className="rounded-lg bg-cyan-500/10 px-2 py-1 text-cyan-400">{macFilters.length} MAC Filters</span>}
                            {wifiSettings && (
                              <a href={`/device/${selectedDevice?.id}`} className="rounded-lg bg-blue-600/20 px-2 py-1 text-blue-400 hover:bg-blue-600/30 transition-colors">
                                Full Config →
                              </a>
                            )}
                          </div>
                        )}
                        {/* WiFi Clients Table */}
                        <div>
                          <h4 className="text-xs font-medium text-zinc-400 uppercase tracking-wider mb-2">Connected Clients {wifiClients.length > 0 ? `(${wifiClients.length})` : ""}</h4>
                          {wifiClients.length > 0 ? (
                            <div className="overflow-x-auto rounded-lg border border-zinc-800">
                              <table className="w-full text-xs">
                                <thead><tr className="border-b border-zinc-800 text-left text-zinc-500">
                                  <th className="px-3 py-2 font-medium">Name</th>
                                  <th className="px-3 py-2 font-medium">IP</th>
                                  <th className="px-3 py-2 font-medium">MAC</th>
                                  <th className="px-3 py-2 font-medium">Band</th>
                                  <th className="px-3 py-2 font-medium">Signal</th>
                                  <th className="px-3 py-2 font-medium">Connected</th>
                                  <th className="px-3 py-2 font-medium">DL</th>
                                  <th className="px-3 py-2 font-medium">Vendor</th>
                                </tr></thead>
                                <tbody>
                                  {wifiClients.map((c: any) => (
                                    <tr key={c.id} className="border-b border-zinc-800/50">
                                      <td className="px-3 py-2 text-zinc-200">{c.name}</td>
                                      <td className="px-3 py-2 text-zinc-400 font-mono">{c.ip}</td>
                                      <td className="px-3 py-2 text-zinc-500 font-mono">{c.mac}</td>
                                      <td className="px-3 py-2"><span className={`rounded px-1.5 py-0.5 ${c.band === "5GHz" ? "bg-blue-500/10 text-blue-400" : "bg-amber-500/10 text-amber-400"}`}>{c.band}</span></td>
                                      <td className={`px-3 py-2 font-mono ${signalColor(c.signal)}`}>{c.signal} dBm</td>
                                      <td className="px-3 py-2 text-zinc-500">{c.connected_since}</td>
                                      <td className="px-3 py-2 text-zinc-400">{c.download_usage}MB</td>
                                      <td className="px-3 py-2 text-zinc-500">{c.vendor}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          ) : (
                            !wifiLoading && <p className="text-xs text-zinc-600 py-2">No clients connected</p>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Chat Messages */}
                <div className="flex-1 overflow-y-auto p-4 space-y-4">
                  {messages.map((msg, i) => (
                    <div key={i} className={`flex flex-col ${msg.role === "user" ? "items-end" : "items-start"}`}>
                      <div className={`max-w-[85%] rounded-2xl px-5 py-3 text-sm leading-relaxed whitespace-pre-wrap ${
                        msg.role === "user" ? "bg-blue-600 text-white" : "bg-zinc-800/80 text-zinc-200"
                      }`}>
                        {msg.text}
                        {msg.actions && msg.actions.length > 0 && (
                          <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-zinc-700/50">
                            {msg.actions.map((a, ai) => (
                              <button key={ai} onClick={() => executeAction(a)} className="rounded-lg px-3 py-1.5 text-xs bg-blue-600/10 text-blue-400 hover:bg-blue-600/20 transition-colors">
                                {a.label}
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                  {isThinking && (
                    <div className="flex justify-start">
                      <div className="bg-zinc-800/80 text-zinc-200 rounded-2xl px-5 py-4 text-sm flex items-center gap-1.5">
                        <span className="animate-bounce" style={{ animationDelay: "0ms" }}>.</span>
                        <span className="animate-bounce" style={{ animationDelay: "150ms" }}>.</span>
                        <span className="animate-bounce" style={{ animationDelay: "300ms" }}>.</span>
                      </div>
                    </div>
                  )}
                  <div ref={chatEndRef} />
                </div>

                {/* Chat Input */}
                <div className="border-t border-zinc-800 p-4">
                  <div className="flex items-center gap-3">
                    <input value={input} onChange={e => setInput(e.target.value)} onKeyDown={e => e.key === "Enter" && handleSend()}
                      placeholder="Ask about your network or type a command..."
                      className="flex-1 rounded-xl border border-zinc-700 bg-zinc-900 px-4 py-3 text-sm text-zinc-100 placeholder-zinc-500 outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-all" />
                    <button onClick={handleSend} className="flex h-11 w-11 items-center justify-center rounded-xl bg-blue-600 text-white hover:bg-blue-500 transition-colors">
                      <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 12h14M12 5l7 7-7 7" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Add Device Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-zinc-100">Add Device</h2>
              <button onClick={() => setShowAddModal(false)} className="text-zinc-500 hover:text-zinc-300 text-xl leading-none">&times;</button>
            </div>
            <div className="mb-6">
              <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">Basic Information</h3>
              <div className="grid grid-cols-2 gap-4">
                <Input label="Device ID" value={addForm.id} onChange={v => setAddForm(f => ({...f, id: v}))} placeholder="e.g. cs-03" />
                <Input label="Hostname" value={addForm.hostname} onChange={v => setAddForm(f => ({...f, hostname: v}))} placeholder="e.g. Core-SW-03" />
                <Input label="IP Address" value={addForm.ip} onChange={v => setAddForm(f => ({...f, ip: v}))} placeholder="10.0.0.3" />
                <Input label="Model" value={addForm.model} onChange={v => setAddForm(f => ({...f, model: v}))} placeholder="e.g. Catalyst 9300" />
                <Select label="Device Type" value={addForm.device_type} onChange={v => setAddForm(f => ({...f, device_type: v}))} options={deviceTypes} />
                <Select label="Vendor" value={addForm.vendor} onChange={v => setAddForm(f => ({...f, vendor: v}))} options={vendors} />
                <Select label="Category" value={addForm.category} onChange={v => setAddForm(f => ({...f, category: v}))} options={deviceCategories.map(c => c.label)} />
                <Input label="Serial Number" value={addForm.serial} onChange={v => setAddForm(f => ({...f, serial: v}))} placeholder="FOC1234ABCD" />
                <Input label="Version" value={addForm.version} onChange={v => setAddForm(f => ({...f, version: v}))} placeholder="17.9.1" />
                <Input label="Tags" value={addForm.tags} onChange={v => setAddForm(f => ({...f, tags: v}))} placeholder="core,datacenter" />
                <Input label="Location" value={addForm.location} onChange={v => setAddForm(f => ({...f, location: v}))} placeholder="DC-1 Rack 01" />
                <div className="col-span-2">
                  <label className="block text-xs text-zinc-400 mb-1">Description</label>
                  <textarea value={addForm.description} onChange={e => setAddForm(f => ({...f, description: e.target.value}))} placeholder="Device purpose..."
                    className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 h-20 resize-none" />
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => setShowAddModal(false)} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800 transition-colors">Cancel</button>
              <button onClick={handleAddDevice} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors">Create Device</button>
            </div>
          </div>
        </div>
      )}

      {/* Device Type Picker */}
      {showDeviceTypePicker && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-md rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-zinc-100">Select Device Type</h2>
              <button onClick={() => setShowDeviceTypePicker(false)} className="text-zinc-500 hover:text-zinc-300 text-xl leading-none">&times;</button>
            </div>
            <div className="grid grid-cols-2 gap-4">
              <button onClick={() => { setShowDeviceTypePicker(false); resetSwitchForm(); setShowSwitchWizard(true); }}
                className="flex flex-col items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-800/50 p-6 hover:border-blue-500/50 hover:bg-zinc-800 transition-colors group">
                <svg className="h-10 w-10 text-zinc-400 group-hover:text-blue-400 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" /></svg>
                <span className="text-sm font-medium text-zinc-300 group-hover:text-blue-300 transition-colors">Switch</span>
                <span className="text-xs text-zinc-500">SSH configuration</span>
              </button>
              <button onClick={() => { setShowDeviceTypePicker(false); resetWifiForm(); setShowWifiWizard(true); }}
                className="flex flex-col items-center gap-3 rounded-xl border border-zinc-700 bg-zinc-800/50 p-6 hover:border-emerald-500/50 hover:bg-zinc-800 transition-colors group">
                <svg className="h-10 w-10 text-zinc-400 group-hover:text-emerald-400 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" /></svg>
                <span className="text-sm font-medium text-zinc-300 group-hover:text-emerald-300 transition-colors">WiFi Router</span>
                <span className="text-xs text-zinc-500">HTTP/HTTPS management</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Credentials Modal */}
      {showCredModal && formCred && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-2xl max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-semibold text-zinc-100">Configure Credentials</h2>
              <button onClick={() => { setShowCredModal(false); setFormCred(null); }} className="text-zinc-500 hover:text-zinc-300 text-xl leading-none">&times;</button>
            </div>
            <div className="mb-6">
              <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">SSH / Telnet</h3>
              <div className="grid grid-cols-2 gap-4">
                <Input label="Username" value={credForm.username} onChange={v => setCredForm(f => ({...f, username: v}))} />
                <Input label="Password" value={credForm.password} onChange={v => setCredForm(f => ({...f, password: v}))} type="password" />
                <Input label="SSH Port" value={String(credForm.ssh_port)} onChange={v => setCredForm(f => ({...f, ssh_port: parseInt(v) || 22}))} />
                <Select label="Auth Type" value={credForm.auth_type} onChange={v => setCredForm(f => ({...f, auth_type: v}))} options={["password", "ssh_key"]} />
                <Input label="Enable Secret" value={credForm.enable_secret} onChange={v => setCredForm(f => ({...f, enable_secret: v}))} type="password" />
                {credForm.auth_type === "ssh_key" && <Input label="SSH Key" value={credForm.ssh_key} onChange={v => setCredForm(f => ({...f, ssh_key: v}))} />}
                {credForm.auth_type === "ssh_key" && <Input label="Passphrase" value={credForm.passphrase} onChange={v => setCredForm(f => ({...f, passphrase: v}))} type="password" />}
              </div>
            </div>
            <div className="mb-6">
              <h3 className="text-sm font-medium text-zinc-400 uppercase tracking-wider mb-3">SNMP</h3>
              <div className="grid grid-cols-2 gap-4">
                <Select label="Version" value={credForm.snmp_version} onChange={v => setCredForm(f => ({...f, snmp_version: v}))} options={["", "v1", "v2c", "v3"]} />
                <Input label="Community" value={credForm.snmp_community} onChange={v => setCredForm(f => ({...f, snmp_community: v}))} type="password" />
              </div>
            </div>
            <div className="mb-6">
              <button onClick={handleTestConnection} className="rounded-lg border border-blue-700 px-4 py-2 text-sm text-blue-400 hover:bg-blue-600/10 transition-colors">Test Connection</button>
              {testResult && <span className={`ml-3 text-sm ${testResult.includes("failed") ? "text-red-400" : "text-green-400"}`}>{testResult}</span>}
            </div>
            <div className="flex justify-end gap-3">
              <button onClick={() => { setShowCredModal(false); setFormCred(null); }} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800 transition-colors">Skip</button>
              <button onClick={handleSaveCredentials} className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors">Save Credentials</button>
            </div>
          </div>
        </div>
      )}

      {/* WiFi Add Router */}
      {showWifiWizard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-zinc-100">Add Wi-Fi Router</h2>
              <button onClick={() => { setShowWifiWizard(false); resetWifiForm(); }} className="text-zinc-500 hover:text-zinc-300 text-xl leading-none">&times;</button>
            </div>

            <div className="space-y-4">
              <Input label="Device Name" value={wifiForm.hostname} onChange={v => setWifiForm(f => ({...f, hostname: v}))} placeholder="Office WiFi Router" />
              <Input label="Management Address" value={wifiForm.mgmt_ip} onChange={v => setWifiForm(f => ({...f, mgmt_ip: v}))} placeholder="192.168.0.1 or tplinkwifi.net" />
              <Input label="Username" value={wifiForm.username} onChange={v => setWifiForm(f => ({...f, username: v}))} placeholder="admin" />
              <Input label="Password" value={wifiForm.password} onChange={v => setWifiForm(f => ({...f, password: v}))} type="password" />
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Connection Method</label>
                <div className="flex gap-2">
                  {["HTTP", "HTTPS"].map(m => (
                    <button key={m} onClick={() => setWifiForm(f => ({...f, mgmt_protocol: m}))}
                      className={`flex-1 rounded-lg border px-4 py-2 text-sm font-medium transition-colors ${wifiForm.mgmt_protocol === m ? "border-emerald-500 bg-emerald-600/20 text-emerald-400" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}>{m}</button>
                  ))}
                </div>
              </div>
            </div>

            <div className="mt-6">
              <button onClick={() => {
                if (!wifiForm.hostname.trim()) { alert("Device Name is required"); return; }
                if (!wifiForm.mgmt_ip.trim()) { alert("Management Address is required"); return; }
                if (!wifiForm.username.trim()) { alert("Username is required"); return; }
                if (!wifiForm.password.trim()) { alert("Password is required"); return; }
                handleTestWifiConnection();
              }} disabled={testStatus === "testing"}
                className="w-full rounded-lg bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-emerald-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                {testStatus === "testing" ? "Testing Connection..." : "Test Connection"}
              </button>
            </div>

            {testStatus === "testing" && (
              <div className="mt-4 text-center">
                <div className="animate-spin inline-block h-5 w-5 border-2 border-emerald-500 border-t-transparent rounded-full" />
                <p className="text-xs text-zinc-500 mt-1">Connecting to {wifiForm.mgmt_ip} via {wifiForm.mgmt_protocol}...</p>
              </div>
            )}

            {testStatus === "failed" && (
              <div className="mt-4 rounded-lg border border-red-800 bg-red-900/20 p-3">
                <p className="text-sm text-red-400 font-medium mb-1">Connection Failed</p>
                <p className="text-xs text-red-300">{testError}</p>
                <button onClick={handleSaveWifiRouter}
                  className="mt-3 w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 transition-colors">
                  Save Anyway
                </button>
              </div>
            )}

            {testStatus === "success" && discoveredInfo && (
              <div className="mt-4 p-4 rounded-lg border border-emerald-800 bg-emerald-900/20">
                <p className="text-green-400 font-medium text-sm mb-3">Connection Successful</p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                  <span className="text-zinc-500">Hostname:</span><span className="text-zinc-200">{discoveredInfo.hostname}</span>
                  <span className="text-zinc-500">Model:</span><span className="text-zinc-200">{discoveredInfo.model}</span>
                  <span className="text-zinc-500">Firmware:</span><span className="text-zinc-200">{discoveredInfo.firmware}</span>
                  <span className="text-zinc-500">WAN Status:</span><span className={discoveredInfo.wan_status === "Connected" ? "text-green-400" : "text-red-400"}>{discoveredInfo.wan_status}</span>
                  <span className="text-zinc-500">Clients:</span><span className="text-zinc-200">{discoveredInfo.connected_clients}</span>
                </div>
                <button onClick={handleSaveWifiRouter}
                  className="mt-4 w-full rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 transition-colors">
                  Save Device
                </button>
              </div>
            )}

            {testStatus === "idle" && (
              <button onClick={handleSaveWifiRouter}
                className="mt-4 w-full rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-400 hover:bg-zinc-800 transition-colors">
                Skip Test & Save Device
              </button>
            )}

            <div className="flex justify-end mt-4">
              <button onClick={() => { setShowWifiWizard(false); resetWifiForm(); }} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Switch Add Wizard */}
      {showSwitchWizard && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-2xl border border-zinc-700 bg-zinc-900 p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-zinc-100">Add Network Switch</h2>
              <button onClick={() => { setShowSwitchWizard(false); resetSwitchForm(); }} className="text-zinc-500 hover:text-zinc-300 text-xl leading-none">&times;</button>
            </div>

            <div className="space-y-4">
              <Input label="IP Address" value={switchForm.ip} onChange={v => setSwitchForm(f => ({...f, ip: v}))} placeholder="10.0.0.1" />
              <div className="grid grid-cols-2 gap-4">
                <Input label="SSH Port" value={String(switchForm.port)} onChange={v => setSwitchForm(f => ({...f, port: parseInt(v) || 22}))} placeholder="22" />
                <Input label="Hostname (optional)" value={switchForm.hostname} onChange={v => setSwitchForm(f => ({...f, hostname: v}))} placeholder="Core-SW-01" />
              </div>
              <Input label="Username" value={switchForm.username} onChange={v => setSwitchForm(f => ({...f, username: v}))} placeholder="admin" />
              <Input label="Password" value={switchForm.password} onChange={v => setSwitchForm(f => ({...f, password: v}))} type="password" />
              <Input label="Enable Secret (optional)" value={switchForm.enable_secret} onChange={v => setSwitchForm(f => ({...f, enable_secret: v}))} type="password" placeholder="Privileged EXEC password" />
              <Select label="SSH Device Type (optional)" value={switchForm.device_type} onChange={v => setSwitchForm(f => ({...f, device_type: v}))} options={sshDeviceTypes} />
            </div>

            <div className="mt-6">
              <button onClick={() => {
                if (!switchForm.ip.trim()) { alert("IP Address is required"); return; }
                if (!switchForm.username.trim()) { alert("Username is required"); return; }
                if (!switchForm.password.trim()) { alert("Password is required"); return; }
                handleTestSwitchConnection();
              }} disabled={switchTestStatus === "testing"}
                className="w-full rounded-lg bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-500 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                {switchTestStatus === "testing" ? "Testing Connection..." : "Test SSH Connection"}
              </button>
            </div>

            {switchTestStatus === "testing" && (
              <div className="mt-4 text-center">
                <div className="animate-spin inline-block h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full" />
                <p className="text-xs text-zinc-500 mt-1">Connecting to {switchForm.ip}:{switchForm.port} via SSH...</p>
              </div>
            )}

            {switchTestStatus === "failed" && (
              <div className="mt-4 rounded-lg border border-red-800 bg-red-900/20 p-3">
                <p className="text-sm text-red-400 font-medium mb-1">Connection Failed</p>
                <p className="text-xs text-red-300">{switchTestError}</p>
                <button onClick={handleSaveSwitch}
                  className="mt-3 w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors">
                  Save Anyway
                </button>
              </div>
            )}

            {switchTestStatus === "success" && switchDiscoveredInfo && (
              <div className="mt-4 p-4 rounded-lg border border-blue-800 bg-blue-900/20">
                <p className="text-blue-400 font-medium text-sm mb-3">Connection Successful</p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-xs">
                  <span className="text-zinc-500">Hostname:</span><span className="text-zinc-200">{switchDiscoveredInfo.hostname}</span>
                  <span className="text-zinc-500">Vendor:</span><span className="text-zinc-200">{switchDiscoveredInfo.vendor}</span>
                  <span className="text-zinc-500">Model:</span><span className="text-zinc-200">{switchDiscoveredInfo.model}</span>
                  <span className="text-zinc-500">Version:</span><span className="text-zinc-200">{switchDiscoveredInfo.version}</span>
                  <span className="text-zinc-500">Serial:</span><span className="text-zinc-200">{switchDiscoveredInfo.serial}</span>
                  <span className="text-zinc-500">Uptime:</span><span className="text-zinc-200">{switchDiscoveredInfo.uptime}</span>
                  <span className="text-zinc-500">Ports:</span><span className="text-zinc-200">{switchDiscoveredInfo.port_count}</span>
                  <span className="text-zinc-500">VLANs:</span><span className="text-zinc-200">{switchDiscoveredInfo.vlan_count}</span>
                </div>
                <button onClick={handleSaveSwitch}
                  className="mt-4 w-full rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 transition-colors">
                  Save Device
                </button>
              </div>
            )}

            {switchTestStatus === "idle" && (
              <button onClick={handleSaveSwitch}
                className="mt-4 w-full rounded-lg border border-zinc-700 px-4 py-2 text-sm font-medium text-zinc-400 hover:bg-zinc-800 transition-colors">
                Skip Test & Save Device
              </button>
            )}

            <div className="flex justify-end mt-4">
              <button onClick={() => { setShowSwitchWizard(false); resetSwitchForm(); }} className="rounded-lg border border-zinc-700 px-4 py-2 text-sm text-zinc-400 hover:bg-zinc-800">Cancel</button>
            </div>
          </div>
        </div>
      )}
      <ToastContainer toasts={toasts} />
    </div>
  );
}
