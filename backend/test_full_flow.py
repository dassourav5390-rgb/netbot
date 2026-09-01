import subprocess, re

# Step 1: fresh login and capture JSESSIONID
# First get RSA params
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi/getParm',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0'],
    capture_output=True, text=True, timeout=15)
nn = re.search(r'var nn="([^"]+)"', r.stdout).group(1)
ee = re.search(r'var ee="([^"]+)"', r.stdout).group(1)
seq = re.search(r'var seq="([^"]+)"', r.stdout).group(1)
print(f'Got RSA params, seq={seq[:10]}...')

# Now simulate browser: login, then access status page, then check if JSESSIONID works for CGI
# Use Python for the crypto parts
import hashlib, base64, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_asym, padding as rsa_padding_mod
from cryptography.hazmat.backends import default_backend

def rsa_encrypt_bytes(data_bytes, nn_hex, ee_hex):
    n, e = int(nn_hex, 16), int(ee_hex, 16)
    pub_key = rsa_asym.RSAPublicNumbers(e, n).public_key(default_backend())
    result = b''
    for i in range(0, len(data_bytes), 53):
        ct = pub_key.encrypt(data_bytes[i:i+53], rsa_padding_mod.PKCS1v15())
        if len(ct) < 64:
            ct = b'\x00' * (64 - len(ct)) + ct
        result += ct
    return result.hex()

def aes_encrypt(p, k, iv):
    pad = padding.PKCS7(128).padder()
    padded = pad.update(p.encode('utf-8')) + pad.finalize()
    c = Cipher(algorithms.AES(k.encode()), modes.CBC(iv.encode()), default_backend())
    return base64.b64encode(c.encryptor().update(padded) + c.encryptor().finalize()).decode()

def aes_decrypt(ct_b64, k, iv):
    ct = base64.b64decode(ct_b64)
    c = Cipher(algorithms.AES(k.encode()), modes.CBC(iv.encode()), default_backend())
    d = c.decryptor()
    p = padding.PKCS7(128).unpadder()
    return (p.update(d.update(ct) + d.finalize()) + p.finalize()).decode()

# Generate keys
key = ''.join([str(random.randint(0,9)) for _ in range(16)])
iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
hsh = hashlib.md5(b'adminAdmin@123').hexdigest()

# Login
lb = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
enc = aes_encrypt(lb, key, iv)
dl = len(enc)
sign_str = f'key={key}&iv={iv}&h={hsh}&s={int(seq) + dl}'
se = rsa_encrypt_bytes(sign_str.encode(), nn, ee)
body = f'sign={se}\r\ndata={enc}\r\n'

with open('/tmp/login_req.txt', 'w') as f:
    f.write(body)

# Login request - this should set JSESSIONID cookie
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?8',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '--data-binary', '@' + '/tmp/login_req.txt',
    '-c', '/tmp/fresh_cookies.txt'],
    capture_output=True, text=True, timeout=15)
if r.stdout:
    print('Login response:', aes_decrypt(r.stdout.strip(), key, iv)[:80])
else:
    print('No login response body')

# Read JSESSIONID from cookie jar
jsid = None
with open('/tmp/fresh_cookies.txt') as f:
    for line in f:
        if 'JSESSIONID' in line and 'deleted' not in line:
            parts = line.strip().split()
            if len(parts) >= 7:
                jsid = parts[6]
print(f'JSESSIONID: {jsid}')

if not jsid:
    print('No JSESSIONID!')
    exit(1)

# Step 2: Access status page to establish session
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/main/status.htm',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Referer: http://192.168.0.1/main/login.htm',
    '-b', '/tmp/fresh_cookies.txt',
    '-c', '/tmp/fresh_cookies.txt',  # update cookies if new ones set
    '-D', '-'],
    capture_output=True, text=True, timeout=15)
print(f'Status page: {len(r.stdout)} bytes')
# Check for Set-Cookie in response
if r.stderr:
    for line in r.stderr.split('\n'):
        if 'Set-Cookie' in line or 'JSESSIONID' in line:
            print(f'  Header: {line.strip()}')

# Step 3: Try encrypted CGI query with fresh session
seq_int = int(seq) + dl  # seq IS updated (like JS behavior after login)
print(f'Seq for query: {seq_int}')

qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
enc2 = aes_encrypt(qb, key, iv)
dl2 = len(enc2)
sign_str2 = f'h={hsh}&s={seq_int + dl2}'  # NO key/iv (like JS for non-login)
se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
body2 = f'sign={se2}\r\ndata={enc2}\r\n'

with open('/tmp/query_req.txt', 'w') as f:
    f.write(body2)

r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?1',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/main/status.htm',  # status page as referer
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '-b', '/tmp/fresh_cookies.txt',
    '--data-binary', '@' + '/tmp/query_req.txt',
    '-D', '-'],
    capture_output=True, text=True, timeout=15)
print(f'Query status line: {r.stderr[-200:] if r.stderr else ""}')
print(f'Query stdout ({len(r.stdout)} bytes): {r.stdout[:500] if r.stdout else "EMPTY"}')
if r.stdout and len(r.stdout) > 100 and not r.stdout.startswith('<'):
    try:
        dec = aes_decrypt(r.stdout.strip(), key, iv)
        print(f'Decrypted: {dec[:500]}')
    except Exception as e:
        print(f'Decrypt error: {e}')
