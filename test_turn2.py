import httpx, json, os, asyncio, sys
sys.path.insert(0, '/app')

TOOL_OUTPUT = """Port     Type         Duplex  Speed Neg      ctrl State       Pressure Mode
-------- ------------ ------  ----- -------- ---- ----------- -------- -------
gi1      1G-Copper      --      --     --     --  Down           --     --    
gi2      1G-Copper      --      --     --     --  Down           --     --    
gi3      1G-Copper      --      --     --     --  Down           --     --    
gi4      1G-Copper      --      --     --     --  Down           --     --    
gi5      1G-Copper    Full    100   Enabled  Off  Up          Disabled Off    
gi6      1G-Copper      --      --     --     --  Down           --     --    
gi7      1G-Copper      --      --     --     --  Down           --     --    
gi8      1G-Copper      --      --     --     --  Down           --     --    
gi9      1G-Copper    Full    1000  Enabled  Off  Up          Disabled On     """

async def test():
    from main import build_system_prompt
    from database import get_devices, get_interfaces, get_vlans, get_logs, get_alerts, get_security_events
    
    devices = await get_devices()
    interfaces = await get_interfaces()
    vlans = await get_vlans()
    logs = await get_logs()
    alerts = await get_alerts()
    sec = await get_security_events()
    
    def fmt(objs):
        if not objs: return 'None'
        return str([str(o)[:100] for o in objs[:3]])
    
    sp = build_system_prompt(fmt(devices), fmt(interfaces), fmt(vlans), fmt(logs), fmt(alerts), fmt(sec), 'None', 'None', 'switch (192.168.1.254) accessible via SSH')
    
    KEY = os.environ.get('OPENROUTER_API_KEY', '')
    model = 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning-20260428:free'
    
    # First turn - the tool call
    messages = [
        {'role': 'system', 'content': sp},
        {'role': 'user', 'content': 'show me the switch interfaces status'}
    ]
    
    resp = httpx.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
        json={
            'model': model,
            'messages': messages,
            'max_tokens': 1000,
            'tools': [{
                'type': 'function',
                'function': {
                    'name': 'execute_switch_command',
                    'description': 'Run CLI command',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'device_id': {'type': 'string'},
                            'commands': {'type': 'string'}
                        },
                        'required': ['device_id', 'commands']
                    }
                }
            }],
            'tool_choice': 'auto',
        },
        timeout=30
    )
    data = resp.json()
    c = data['choices'][0]
    msg = c['message']
    print(f'Turn 1 finish: {c.get("finish_reason")}')
    
    # Append assistant message with tool calls
    messages.append(msg)
    
    # Append tool result
    for tc in msg.get('tool_calls', []):
        messages.append({
            'role': 'tool',
            'tool_call_id': tc['id'],
            'content': TOOL_OUTPUT
        })
    
    # Second turn
    print(f'Turn 2 messages count: {len(messages)}')
    print(f'Turn 2 total chars: {sum(len(str(m)) for m in messages)}')
    
    resp = httpx.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
        json={
            'model': model,
            'messages': messages,
            'max_tokens': 1000,
            'tools': [{
                'type': 'function',
                'function': {
                    'name': 'execute_switch_command',
                    'description': 'Run CLI command',
                    'parameters': {
                        'type': 'object',
                        'properties': {
                            'device_id': {'type': 'string'},
                            'commands': {'type': 'string'}
                        },
                        'required': ['device_id', 'commands']
                    }
                }
            }],
            'tool_choice': 'auto',
        },
        timeout=60
    )
    data = resp.json()
    if 'choices' in data:
        c = data['choices'][0]
        fr = c.get('finish_reason')
        msg2 = c['message']
        content = msg2.get('content', '') or ''
        print(f'Turn 2 finish: {fr}')
        print(f'Turn 2 content: {content[:500]}')
    elif 'error' in data:
        print(f'Turn 2 error: {json.dumps(data["error"])[:500]}')
    else:
        print(f'Turn 2 unexpected: {json.dumps(data)[:500]}')

asyncio.run(test())
