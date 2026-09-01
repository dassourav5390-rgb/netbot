import httpx, json

KEY = "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"
models = ['qwen/qwen-2.5-7b-instruct:free', 'deepseek/deepseek-v3:free', 'google/gemini-2.0-flash-001', 'mistral/mistral-small-24b-instruct-2501:free']
for model in models:
    try:
        resp = httpx.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
            json={'model': model, 'messages': [{'role': 'user', 'content': 'say hello'}], 'max_tokens': 50},
            timeout=15
        )
        data = resp.json()
        if 'error' in data:
            print(f'{model}: ERROR - {str(data["error"])[:120]}')
            continue
        c = data['choices'][0]
        print(f'{model}: OK - finish={c["finish_reason"]}')
    except Exception as e:
        print(f'{model}: Exception - {e}')
