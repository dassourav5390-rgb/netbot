import re
with open('/tmp/status.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Find CGI response blocks embedded in JavaScript strings
# They appear as: "\\n[0,0,0,0,0,0]0\\n..."
patterns = re.findall(r'\\n\[([\d,]+)\]\d+\\n', html)
print('Found', len(patterns), 'CGI stack references')

# Find all OID=data patterns
# Look for SSID, key_passphrase, etc.
for line in html.split('\\n'):
    line = line.strip()
    if 'SSID=' in line or 'key_passphrase=' in line or 'PreSharedKey=' in line or 'enable=' in line or 'channel=' in line:
        print(line[:200])

# Also search for raw data patterns in the HTML itself (not escaped)
raw_blocks = re.findall(r'\[[\d,]+\]\d+\n([^[]+)', html)
print('\n--- Raw CGI blocks ---')
for b in raw_blocks[:10]:
    print(b[:300])
    print('===')

# Search for wlan-specific data
for kw in ['wlanssid', 'wl_channel', 'wl_radio', 'key_passphrase', 'PreSharedKey']:
    matches = [l for l in html.split('\n') if kw.lower() in l.lower()]
    for m in matches[:3]:
        print(kw + ':', m.strip()[:200])
