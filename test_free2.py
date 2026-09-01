import httpx, json

KEY = "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"
models = ['openrouter/free', 'meta-llama/llama-3.2-3b-instruct:free', 'deepseek/deepseek-chat:free']
for model in models:
    try:
        resp = httpx.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
            json={
                'model': model,
                'messages': [{'role': 'user', 'content': 'list 3 colors'}],
                'max_tokens': 100,
                'tools': [{
                    'type': 'function',
                    'function': {
                        'name': 'test_tool',
                        'description': 'A test tool',
                        'parameters': {'type': 'object', 'properties': {'x': {'type': 'string'}}}
                    }
                }],
                'tool_choice': 'auto',
            },
            timeout=30
        )
        data = resp.json()
        if 'error' in data:
            print(f'{model}: ERROR - {str(data["error"])[:150]}')
            continue
        c = data['choices'][0]
        has_tc = bool(c['message'].get('tool_calls'))
        print(f'{model}: OK - finish={c["finish_reason"]}, has_tool_calls={has_tc}')
        if not has_tc:
            print(f'  content: {(c["message"].get("content") or "")[:100]}')
    except Exception as e:
        print(f'{model}: Exception - {str(e)[:150]}')
