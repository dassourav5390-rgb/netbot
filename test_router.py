import httpx, json

KEY = "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"
resp = httpx.post(
    'https://openrouter.ai/api/v1/chat/completions',
    headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
    json={'model': 'openrouter/free', 'messages': [{'role':'user','content':'say hi'}], 'max_tokens': 50},
    timeout=15
)
data = resp.json()
if 'choices' in data:
    print(f'Model: {data.get("model", "unknown")}')
    print(f'Provider: {data.get("provider", "unknown")}')
    c = data['choices'][0]
    print(f'Finish: {c.get("finish_reason")}')
    print(f'Content: {(c["message"].get("content") or "")[:200]}')
elif 'error' in data:
    print(f'Error: {json.dumps(data["error"])[:300]}')
else:
    print(f'Unexpected: {json.dumps(data)[:300]}')
