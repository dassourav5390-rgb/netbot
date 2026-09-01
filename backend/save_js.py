import urllib.request
req = urllib.request.Request('http://192.168.0.1/js/lib.js', headers={
    'Referer': 'http://192.168.0.1/',
    'User-Agent': 'Mozilla/5.0'
})
r = urllib.request.urlopen(req, timeout=5)
c = r.read().decode('utf-8', errors='replace')
open('/tmp/lib.js', 'w').write(c)
print('Saved', len(c), 'bytes')
