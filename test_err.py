import httpx, json, os

KEY = os.environ.get('OPENROUTER_API_KEY', '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')
model = 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning-20260428:free'

resp = httpx.post(
    'https://openrouter.ai/api/v1/chat/completions',
    headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
    json={'model': model, 'messages': [{'role':'user','content':'hi'}], 'max_tokens': 50},
    timeout=15
)
data = resp.json()
if 'error' in data:
    msg = data['error'].get('message', str(data['error']))
    code = data['error'].get('code', 0)
    print(f'Error code: {code}')
    print(f'Error msg: {msg[:300]}')
else:
    c = data['choices'][0]
    print(f'OK: finish={c["finish_reason"]}')
