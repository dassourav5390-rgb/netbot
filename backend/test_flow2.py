import subprocess, re, hashlib, base64, random
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
    try:
        ct = base64.b64decode(ct_b64)
        c = Cipher(algorithms.AES(k.encode()), modes.CBC(iv.encode()), default_backend())
        d = c.decryptor()
        p = padding.PKCS7(128).unpadder()
        return (p.update(d.update(ct) + d.finalize()) + p.finalize()).decode()
    except Exception as e:
        return f'DECRYPT_ERROR: {e}'

# Get RSA params
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi/getParm',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0'],
    capture_output=True, text=True, timeout=15)
nn = re.search(r'var nn="([^"]+)"', r.stdout).group(1)
ee = re.search(r'var ee="([^"]+)"', r.stdout).group(1)
seq_int = int(re.search(r'var seq="([^"]+)"', r.stdout).group(1))
print('Initial seq:', seq_int)

key = ''.join([str(random.randint(0,9)) for _ in range(16)])
iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
hsh = hashlib.md5(b'adminAdmin@123').hexdigest()

# Login
lb = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
enc = aes_encrypt(lb, key, iv)
dl = len(enc)
sign_str = f'key={key}&iv={iv}&h={hsh}&s={seq_int + dl}'
se = rsa_encrypt_bytes(sign_str.encode(), nn, ee)
body = f'sign={se}\r\ndata={enc}\r\n'
with open('/tmp/lb.txt', 'w') as f:
    f.write(body)

r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?8',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '--data-binary', '@' + '/tmp/lb.txt',
    '-c', '/tmp/cookies3.txt'],
    capture_output=True, text=True, timeout=15)
login_resp = r.stdout.strip()
if login_resp:
    print('Login:', aes_decrypt(login_resp, key, iv)[:80])

# Get JSESSIONID from cookie file
jsid = None
with open('/tmp/cookies3.txt') as f:
    for line in f:
        if 'JSESSIONID' in line and 'deleted' not in line:
            parts = line.strip().split()
            if len(parts) >= 7:
                jsid = parts[6]
print(f'JSID: {jsid}')

if not jsid:
    print('FAIL: No JSESSIONID')
    exit(1)

# Now verify cookie works by accessing status page
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/main/status.htm',
    '-H', 'User-Agent: Mozilla/5.0',
    '-b', '/tmp/cookies3.txt',
    '-D', '-'],
    capture_output=True, text=True, timeout=15)
# Print Set-Cookie from stderr (headers from -D are in stdout)
for line in r.stdout.split('\n'):
    if 'JSESSIONID' in line or 'Set-Cookie' in line:
        print(f'Status header: {line.strip()}')
body_start = r.stdout.find('\r\n\r\n')
if body_start > 0:
    body = r.stdout[body_start+4:]
    print(f'Status page: {len(body)} bytes')

# Try encrypted CGI query with curl, capturing full response
query_body = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
# Use ORIGINAL seq (no update after login) - like JS behavior
enc2 = aes_encrypt(query_body, key, iv)
dl2 = len(enc2)
sign_str2 = f'h={hsh}&s={seq_int + dl2}'  # seq_int is initial seq (not updated)
se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
body2 = f'sign={se2}\r\ndata={enc2}\r\n'
with open('/tmp/qb.txt', 'w') as f:
    f.write(body2)

# Try with Content-Type: text/plain
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?1',
    '-H', 'Content-Type: text/plain',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-b', '/tmp/cookies3.txt',
    '--data-binary', '@' + '/tmp/qb.txt',
    '-D', '-'],
    capture_output=True, text=True, timeout=15)
print(f'\nQuery response ({len(r.stdout)} bytes):')
# Show headers and body
header_end = r.stdout.find('\r\n\r\n')
if header_end > 0:
    print('Headers:')
    print(r.stdout[:header_end])
    body = r.stdout[header_end+4:]
    print(f'Body ({len(body)} bytes): {body[:500]}')
else:
    print(r.stdout[:500])
