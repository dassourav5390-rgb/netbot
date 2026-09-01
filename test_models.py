import httpx, json, os, time

KEY = os.environ.get('OPENROUTER_API_KEY', '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')

# Try the openrouter/free router which auto-picks available models
for attempt in range(3):
    print(f'Testing openrouter/free (attempt {attempt+1})...')
    try:
        resp = httpx.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {KEY}', 'Content-Type': 'application/json'},
            json={
                'model': 'openrouter/free',
                'messages': [{'role':'user','content':'say hi in 2 words'}],
                'max_tokens': 20,
            },
            timeout=20
        )
        data = resp.json()
        if 'error' in data:
            msg = data['error'].get('message', '?')
            print(f'  FAIL: {msg[:120]}')
            if 'free-models-per-day' in msg:
                break
            time.sleep(3)
        else:
            content = data['choices'][0]['message']['content']
            model_used = data.get('model', '?')
            print(f'  OK: model={model_used}, response="{content.strip()}"')
            break
    except Exception as e:
        print(f'  EXCEPTION: {str(e)[:80]}')
        time.sleep(3)
