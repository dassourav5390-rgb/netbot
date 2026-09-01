import httpx, json

KEY = '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'
model = 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning-20260428:free'

system = '''You are NetBot AI, a Cisco Network Engineer.
DEVICES:
- switch (id: switch, ip: 192.168.1.254, Cisco SG300, online, cpu: 55%)
- TP-Link Router (id: 192-168-0-1, ip: 192.168.0.1, TP-Link, online)

INTERFACES:
- gi1: Down, gi2: Down, gi3: Down, gi4: Down
- gi5: Up, gi6: Down, gi7: Down, gi8: Down
- gi9: Up, gi10-28: Down

COMMANDS: You have execute_switch_command tool.
When asked about interfaces status on switch, run: show interfaces status'''

resp = httpx.post(
    'https://openrouter.ai/api/v1/chat/completions',
    headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
    json={
        'model': model,
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': 'show me the switch interfaces status'}
        ],
        'max_tokens': 500,
        'tools': [{
            'type': 'function',
            'function': {
                'name': 'execute_switch_command',
                'description': 'Run a CLI command on a switch via SSH',
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
if 'choices' in data:
    c = data['choices'][0]
    fr = c.get('finish_reason')
    msg = c['message']
    content = msg.get('content', '') or ''
    tc = msg.get('tool_calls')
    print(f'Finish reason: {fr}')
    print(f'Has tool_calls: {bool(tc)}')
    print(f'Content: {content[:500]}')
    if tc:
        for t in tc:
            print(f'Tool: {t["function"]["name"]} args: {t["function"]["arguments"]}')
elif 'error' in data:
    print(f'Error: {json.dumps(data["error"])[:500]}')
else:
    print(f'Response: {json.dumps(data)[:500]}')
