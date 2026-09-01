import urllib.request, json

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/devices', 
    headers={
        'X-NetBot-Api-Key': 'netbot-api-key-2026',
        'Origin': 'http://localhost:3000'
    }
)
resp = urllib.request.urlopen(req, timeout=10)
devices = json.loads(resp.read())
print(f'API returns {len(devices)} devices:')
for d in devices:
    print(f'  - {d["hostname"]} ({d["status"]})')
