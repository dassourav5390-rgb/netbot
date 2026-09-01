import os, urllib.request
token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
if not token:
    print("NO TOKEN"); exit(1)
try:
    r = urllib.request.urlopen(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
    print(r.read().decode()[:300])
except Exception as e:
    print(f"FAILED: {e}")
