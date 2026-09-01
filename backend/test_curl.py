import httpx, hashlib, base64, random, re, subprocess, sys
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

# Get RSA params
r = httpx.get('http://192.168.0.1/cgi/getParm', headers={
    'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
    'User-Agent': 'Mozilla/5.0'
})
nn = re.search(r'var nn="([^"]+)"', r.text).group(1)
ee = re.search(r'var ee="([^"]+)"', r.text).group(1)
seq_str = re.search(r'var seq="([^"]+)"', r.text).group(1)
seq_int = int(seq_str)
print('Initial seq:', seq_int)

key = ''.join([str(random.randint(0,9)) for _ in range(16)])
iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
hsh = hashlib.md5(b'adminAdmin@123').hexdigest()

# Login
lb = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
le = aes_encrypt(lb, key, iv)
dl = len(le)
ss = f'key={key}&iv={iv}&h={hsh}&s={seq_int + dl}'
se = rsa_encrypt_bytes(ss.encode(), nn, ee)
pb = f'sign={se}\r\ndata={le}\r\n'

r = httpx.post('http://192.168.0.1/cgi_gdpr?8', content=pb, headers={
    'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
    'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'
})
jsid = r.cookies.get('JSESSIONID')
dec = aes_decrypt(r.text, key, iv)
print('Login JSID:', jsid, '| Response:', dec[:80])
seq_int += dl

# Now use curl for the query
qb = '6\r\n[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,8\r\nleaseIP\r\nleaseMAC\r\nhostName\r\n'
qe = aes_encrypt(qb, key, iv)
qdl = len(qe)
ss2 = f'key={key}&iv={iv}&h={hsh}&s={seq_int + qdl}'
se2 = rsa_encrypt_bytes(ss2.encode(), nn, ee)
pb2 = f'sign={se2}\r\ndata={qe}\r\n'

# Save to temp file for curl
with open('/tmp/post_body.txt', 'w') as f:
    f.write(pb2)

print(f'\nQuery seq: {seq_int + qdl}')
print(f'Sign string: {ss2}')
print(f'Post body length: {len(pb2)}')

import os
# Use curl from Python
curl_cmd = [
    'curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?6',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '-H', 'Cookie: JSESSIONID=' + jsid,
    '--data-binary', '@' + '/tmp/post_body.txt',
    '-v'
]
result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=15)
print('\nCurl stdout:', result.stdout[:500] if result.stdout else 'EMPTY')
print('Curl stderr:', result.stderr[:500] if result.stderr else 'EMPTY')
print('Curl returncode:', result.returncode)

if result.stdout:
    try:
        dec2 = aes_decrypt(result.stdout.strip(), key, iv)
        print('\nDecrypted response:', dec2[:500])
    except Exception as e:
        print('Decryption error:', e)
