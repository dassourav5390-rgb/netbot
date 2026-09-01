# AI Chat Generation with Llama 3.1 8B Free - Implementation Plan

## Changes Required

### 1. `backend/main.py` - Change Model (line 45)

**Before:**
```python
OPENROUTER_MODEL = "deepseek/deepseek-chat-v3"
```

**After:**
```python
OPENROUTER_MODEL = "meta-llama/llama-3.1-8b-instruct:free"
```

---

### 2. `backend/main.py` - Add New Tool Definitions (after line 475, after EXECUTE_COMMAND_TOOL)

Insert these three new tool definitions after the `EXECUTE_COMMAND_TOOL` block (after line 475):

```python
SCAN_NETWORK_TOOL = {
    "type": "function",
    "function": {
        "name": "scan_network",
        "description": "Run a network discovery scan to find all connected devices on the local subnet. "
                       "Uses nmap ping scan and ARP scan to discover hosts, resolve MAC addresses and vendors. "
                       "Call this when the user asks to 'show networks', 'scan network', 'find devices', "
                       "'discover hosts', or wants to see what's connected to the network.",
        "parameters": {
            "type": "object",
            "properties": {
                "network": {
                    "type": "string",
                    "description": "Optional network CIDR to scan (e.g. '192.168.0.0/24'). "
                                   "If empty, the system will auto-detect from router IP.",
                    "default": ""
                }
            }
        }
    }
}

BLOCK_WIFI_CLIENT_TOOL = {
    "type": "function",
    "function": {
        "name": "block_wifi_client",
        "description": "Block a WiFi client by MAC address on a specific WiFi router. "
                       "This adds a MAC address filter to deny the device from connecting. "
                       "Call this when the user asks to 'block wifi', 'block a device', "
                       "'kick off', 'ban' a client, or 'block mac'.",
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string",
                    "description": "The ID of the WiFi router device to block on. Look up the correct device_id from the NETWORK DEVICES list (find the WiFi Router)."
                },
                "mac": {
                    "type": "string",
                    "description": "The MAC address of the client to block (e.g. 'AA:BB:CC:DD:EE:FF'). Case insensitive."
                },
                "name": {
                    "type": "string",
                    "description": "Optional friendly name/description for the blocked client.",
                    "default": ""
                },
                "band": {
                    "type": "string",
                    "description": "Optional WiFi band: '2.4GHz' or '5GHz'. If empty, blocks on both bands.",
                    "default": ""
                }
            },
            "required": ["device_id", "mac"]
        }
    }
}

UNBLOCK_WIFI_CLIENT_TOOL = {
    "type": "function",
    "function": {
        "name": "unblock_wifi_client",
        "description": "Unblock a previously blocked WiFi client by MAC address. "
                       "Removes the MAC filter entry from the router. "
                       "Call this when the user asks to 'unblock wifi', 'unblock a device', "
                       "'allow' a previously blocked client.",
        "parameters": {
            "type": "object",
            "properties": {
                "device_id": {
                    "type": "string",
                    "description": "The ID of the WiFi router device to unblock on."
                },
                "mac": {
                    "type": "string",
                    "description": "The MAC address of the client to unblock (e.g. 'AA:BB:CC:DD:EE:FF')."
                }
            },
            "required": ["device_id", "mac"]
        }
    }
}
```

---

### 3. `backend/main.py` - Update `call_openrouter` function (starts at line 2381)

Replace the entire `call_openrouter` function:

```python
async def call_openrouter(system_prompt: str, history: list[dict], user_message: str,
                          device_id: str | None = None) -> tuple[str, list[dict]]:
    messages = [{"role": "system", "content": system_prompt}]
    for h in history:
        messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": user_message})

    # Build tools list: always include network tools, conditionally include SSH
    tools = [SCAN_NETWORK_TOOL, BLOCK_WIFI_CLIENT_TOOL, UNBLOCK_WIFI_CLIENT_TOOL]
    if device_id:
        tools.append(EXECUTE_COMMAND_TOOL)

    max_turns = 6
    for turn in range(max_turns):
        body = {
            "model": OPENROUTER_MODEL,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 2000,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=60) as client:
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
                name = tc["function"]["name"]
                try:
                    args = json.loads(tc["function"]["arguments"])
                except (json.JSONDecodeError, KeyError):
                    args = {}

                if name == "execute_switch_command":
                    commands = args.get("commands", "")
                    result = await _execute_on_device(device_id or "", commands)
                    content = result.get("output", "")
                elif name == "scan_network":
                    network = args.get("network", "")
                    try:
                        result = await _run_network_scan("ai", network, "ai_triggered")
                        hosts = result.get("hosts", [])
                        summary = (
                            f"Network scan completed. Found {result['hosts_found']} hosts "
                            f"(online: {result['hosts_online']}, offline: {result['hosts_offline']}, "
                            f"new: {result['new_devices']}, anomalies: {result['anomalies']}). "
                            f"Duration: {result['duration_sec']}s.\n\n"
                        )
                        if hosts:
                            summary += "Discovered hosts:\n" + "\n".join(
                                f"- {h.hostname or '?'} ({h.ip}) | MAC: {h.mac or '?'} | Vendor: {h.vendor or '?'} | Status: {h.status}{' [NEW]' if h.is_new else ''}{' [DUP_IP]' if h.is_duplicate_ip else ''}{' [DUP_MAC]' if h.is_duplicate_mac else ''}"
                                for h in hosts[:60]
                            )
                            if len(hosts) > 60:
                                summary += f"\n... and {len(hosts) - 60} more hosts"
                        else:
                            summary += "No hosts discovered."
                        content = summary
                    except Exception as e:
                        content = f"Network scan failed: {str(e)}"
                elif name == "block_wifi_client":
                    device_id_arg = args.get("device_id", "")
                    mac = args.get("mac", "").strip().upper()
                    name_arg = args.get("name", "")
                    band = args.get("band", "")
                    if not device_id_arg or not mac:
                        content = "Missing required parameters: device_id and mac are required."
                    else:
                        try:
                            d = await get_device(device_id_arg)
                            if not d:
                                content = f"Device '{device_id_arg}' not found. Available WiFi routers: check NETWORK DEVICES list."
                            else:
                                req_body = BlockClientRequest(mac=mac, band=band, name=name_arg)
                                result = await wifi_block_client(device_id_arg, req_body)
                                content = f"Successfully blocked {mac} on {d.hostname} ({d.ip}). The client will no longer be able to connect to the WiFi network."
                        except HTTPException as e:
                            content = f"Failed to block client: {e.detail}"
                        except Exception as e:
                            content = f"Failed to block client: {str(e)}"
                elif name == "unblock_wifi_client":
                    device_id_arg = args.get("device_id", "")
                    mac = args.get("mac", "").strip().upper()
                    if not device_id_arg or not mac:
                        content = "Missing required parameters: device_id and mac are required."
                    else:
                        try:
                            d = await get_device(device_id_arg)
                            if not d:
                                content = f"Device '{device_id_arg}' not found."
                            else:
                                req_body = BlockClientRequest(mac=mac)
                                result = await wifi_unblock_client(device_id_arg, req_body)
                                content = f"Successfully unblocked {mac} on {d.hostname} ({d.ip}). The client can now connect to the WiFi network again."
                        except HTTPException as e:
                            content = f"Failed to unblock client: {e.detail}"
                        except Exception as e:
                            content = f"Failed to unblock client: {str(e)}"
                else:
                    content = f"Unknown tool: {name}"

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": content[:3000],
                })
            continue

        content = msg.get("content", "")
        try:
            parsed = json.loads(content)
            return parsed.get("reply", content), parsed.get("actions", [])
        except (json.JSONDecodeError, KeyError):
            return content, []

    return "I couldn't complete that request in the available steps. Please try a simpler query.", []
```

---

### 4. `backend/main.py` - Update System Prompt (starts at line 2299)

Replace the `build_system_prompt` function. Key changes:
- Added "## TOOLS AVAILABLE TO YOU" section after "YOUR CAPABILITIES"
- Describes all 4 tools with natural language triggers for each
- Mentions router IDs and MAC addresses context for blocking

```python
def build_system_prompt(devices_str: str, interfaces_str: str, vlans_str: str,
                         logs_str: str, alerts_str: str, sec_events_str: str,
                         wifi_clients_str: str = "", wifi_guests_str: str = "",
                         discovered_str: str = "", device_context: str = "") -> str:
    return f"""You are NetBot AI, an expert network operations assistant for enterprise environments. You support Cisco, Juniper, Aruba, Fortinet, MikroTik, Huawei, TP-Link, D-Link, Netgear, ASUS, Linksys, and Ubiquiti.

You have real-time access to the following network data. Use it to answer questions accurately.

## NETWORK DEVICES
{devices_str}

## INTERFACES
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
- **Wi-Fi Management**: Connected client analysis, signal strength, band steering, channel optimization, guest user tracking
- **Security**: Rogue device detection, login monitoring, port security violations, unknown device detection, network scan anomalies
- **Automation**: Config backups, compliance checks, VLAN creation previews
- **Reporting**: Health reports, compliance reports, security summaries, daily Wi-Fi reports
- **Network Discovery**: Scan network to find all connected devices, detect new/unknown devices, identify duplicate IPs/MACs
- **SSH Device Access**: When a device is selected, you can run live CLI commands on it using the `execute_switch_command` tool.

## TOOLS AVAILABLE TO YOU
You have the following tools at your disposal. Use them when the user's request requires action beyond your existing data.

### 1. execute_switch_command
For running live SSH commands on a selected network device. Use this when the user selects a device and asks for real-time data not in the context above, or wants to make configuration changes.
- Run show commands to inspect interfaces, VLANs, MAC tables, ARP tables, running config, etc.
- For multi-step lookups (e.g. find IP → get MAC → find port), make multiple tool calls sequentially.
- For configuration changes (e.g. shutdown a port), ALWAYS describe the change and ask the user to confirm before executing.
- For multi-line config changes, send commands separated by \\n.
- After completing config changes, verify with appropriate show commands.

### 2. scan_network
Run a network discovery scan to find all connected devices. Use this when the user says:
- "Show networks" or "show all devices on the network"
- "Scan the network" or "run a network scan"
- "Find devices" or "discover hosts"
- "What's connected to my network?"
- This will perform an nmap ping scan + ARP scan + DNS resolution.
- After scanning, you will receive a detailed list of discovered hosts with IPs, MACs, vendors, and status.

### 3. block_wifi_client
Block a WiFi client by MAC address on a specific router. Use this when the user says:
- "Block this device" or "block this MAC"
- "Kick off [device] from WiFi"
- "Ban [MAC address] from the network"
- "Stop [device] from connecting"
- You need the device_id (router ID) and the MAC address of the client.
- The available WiFi routers and their device IDs are listed in NETWORK DEVICES above.
- The connected WiFi clients with their MAC addresses are listed in WIFI ROUTER DATA above.

### 4. unblock_wifi_client
Unblock a previously blocked WiFi client by MAC address. Use this when the user says:
- "Unblock this device" or "unblock this MAC"
- "Allow [MAC address] back on the network"
- "Remove the block on [device]"

## WiFi-SPECIFIC RULES
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
2. When troubleshooting interfaces (e.g. "why is Gi1/0/10 down"), analyze the interface status, errors, STP state, logs, and alerts to identify root cause.
3. Provide structured responses with headings and bullet points.
4. For automation actions (non-SSH), include an "actions" field in your response JSON when applicable.
5. Keep responses concise but thorough — network engineers need precise technical details.
6. Use markdown formatting for readability.
7. Flag security issues and compliance gaps when relevant.

Respond in JSON format with fields: "reply" (your markdown response) and "actions" (array of action objects, empty if none). Each action has "type", "label", and optionally "device" / "interface" / "client"."""
```

---

### 5. `my-app/app/page.tsx` - Update Frontend `handleSend` to Process Actions

Find the `handleSend` function (around line 225) and update it. Add a `handleAction` function and modify `handleSend`:

**Add after `handleSend` (after line 238):**
```typescript
  const handleAction = async (action: any) => {
    if (action.type === "refresh" && action.target === "scan") {
      await fetchScanSummary();
      await fetchScanHistory();
      setMessages((prev) => [...prev, { role: "ai", text: "Scan data refreshed." }]);
    } else if (action.type === "refresh" && action.target === "wifi") {
      if (selectedDevice?.device_type === "WiFi Router") {
        await fetchWifiData(selectedDevice.id);
        setMessages((prev) => [...prev, { role: "ai", text: "WiFi data refreshed." }]);
      }
    } else if (action.type === "scan_network") {
      await handleScanNetwork();
      setMessages((prev) => [...prev, { role: "ai", text: "Network scan triggered. Check the dashboard for results." }]);
    }
  };
```

**Replace the `handleSend` function body after the fetch call (lines 235-237):**
```typescript
      const data = await res.json();
      setMessages((prev) => [...prev, { role: "ai", text: data.reply }]);
      // Process any actions returned from the AI
      if (data.actions && data.actions.length > 0) {
        for (const action of data.actions) {
          await handleAction(action);
        }
      }
```
