import httpx, json, os, asyncio, sys
sys.path.insert(0, '/app')

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
    print(f'System prompt length: {len(sp)} chars')
    
    KEY = os.environ.get('OPENROUTER_API_KEY', '')
    model = 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning-20260428:free'
    
    resp = httpx.post(
        'https://openrouter.ai/api/v1/chat/completions',
        headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
        json={
            'model': model,
            'messages': [
                {'role': 'system', 'content': sp},
                {'role': 'user', 'content': 'show me the switch interfaces status'}
            ],
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
        msg = c['message']
        content = msg.get('content', '') or ''
        tc = msg.get('tool_calls')
        print(f'Finish reason: {fr}')
        print(f'Has tool_calls: {bool(tc)}')
        print(f'Content length: {len(content)}')
        print(f'Content: {content[:300]}')
        if tc:
            for t in tc:
                fn = t['function']
                print(f'Tool: {fn["name"]} args: {fn["arguments"][:200]}')
    elif 'error' in data:
        err = data['error']
        print(f'Error: {json.dumps(err)[:500]}')
    else:
        print(f'Unexpected: {json.dumps(data)[:500]}')

asyncio.run(test())
