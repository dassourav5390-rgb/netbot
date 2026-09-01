import sys, os, hashlib, base64, random, re
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

import subprocess

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
    '-c', '/tmp/cookies.txt'],
    capture_output=True, text=True, timeout=15)
jsid = None
if os.path.exists('/tmp/cookies.txt'):
    with open('/tmp/cookies.txt') as f:
        for line in f:
            if 'JSESSIONID' in line and 'deleted' not in line:
                parts = line.strip().split()
                if len(parts) >= 7:
                    jsid = parts[6]
print('JSID:', jsid)
if not jsid:
    exit()
seq_int += dl

# Test reversed order: data before sign
print('\n--- Test: data before sign ---')
qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
enc2 = aes_encrypt(qb, key, iv)
dl2 = len(enc2)
sign_str2 = f'h={hsh}&s={seq_int + dl2}'
se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
# REVERSED ORDER
body2 = f'data={enc2}\r\nsign={se2}\r\n'
with open('/tmp/qb.txt', 'w') as f:
    f.write(body2)
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?1',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '-b', '/tmp/cookies.txt',
    '--data-binary', '@' + '/tmp/qb.txt'],
    capture_output=True, text=True, timeout=15)
print('stdout:', r.stdout[:200] if r.stdout else 'EMPTY')
print('stderr:', r.stderr[-300:] if r.stderr else '')

# Test: use \n instead of \r\n
print('\n--- Test: \\n line endings ---')
qb3 = '1\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\n'
enc3 = aes_encrypt(qb3, key, iv)
dl3 = len(enc3)
sign_str3 = f'h={hsh}&s={seq_int + dl2 + dl3}'  # Use updated seq
se3 = rsa_encrypt_bytes(sign_str3.encode(), nn, ee)
body3 = f'sign={se3}\r\ndata={enc3}\r\n'
with open('/tmp/qb3.txt', 'w') as f:
    f.write(body3)
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?1',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '-b', '/tmp/cookies.txt',
    '--data-binary', '@' + '/tmp/qb3.txt'],
    capture_output=True, text=True, timeout=15)
print('stdout:', r.stdout[:200] if r.stdout else 'EMPTY')
print('stderr:', r.stderr[-300:] if r.stderr else '')

# Test: different body - use the exact format that works for login CGI
print('\n--- Test: use ACT_GET with LAN_WLAN_MULTISSID (no attrs) ---')
qb4 = '1\n[LAN_WLAN_MULTISSID#0,0,0,0,0,0#0,0,0,0,0,0]0,0\n'
enc4 = aes_encrypt(qb4, key, iv)
dl4 = len(enc4)
sign_str4 = f'h={hsh}&s={seq_int + dl2 + dl3 + dl4}'
se4 = rsa_encrypt_bytes(sign_str4.encode(), nn, ee)
body4 = f'sign={se4}\r\ndata={enc4}\r\n'
with open('/tmp/qb4.txt', 'w') as f:
    f.write(body4)
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?1',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '-b', '/tmp/cookies.txt',
    '--data-binary', '@' + '/tmp/qb4.txt'],
    capture_output=True, text=True, timeout=15)
print('stdout:', r.stdout[:500] if r.stdout else 'EMPTY')
print('stderr:', r.stderr[-300:] if r.stderr else '')
