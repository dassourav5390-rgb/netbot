import httpx, json, os

KEY = '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'
model = 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning-20260428:free'

resp = httpx.post(
    'https://openrouter.ai/api/v1/chat/completions',
    headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
    json={
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'You are a network assistant. Answer briefly.'},
            {'role': 'user', 'content': 'list the interfaces on the switch'}
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
                        'device_id': {'type': 'string', 'description': 'Device ID'},
                        'commands': {'type': 'string', 'description': 'CLI commands'}
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
    print(f'Content length: {len(content)}')
    print(f'Content: {content[:300]}')
    if tc:
        for t in tc[:2]:
            print(f'Tool: {t["function"]["name"]}')
elif 'error' in data:
    print(f'Error: {json.dumps(data["error"])[:500]}')
else:
    print(f'Unexpected: {json.dumps(data)[:500]}')
