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

# Use subprocess to call curl
import subprocess

# Get RSA params
r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi/getParm',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0'],
    capture_output=True, text=True, timeout=15)
output = r.stdout
nn = re.search(r'var nn="([^"]+)"', output).group(1)
ee = re.search(r'var ee="([^"]+)"', output).group(1)
seq_int = int(re.search(r'var seq="([^"]+)"', output).group(1))
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

# Save body to temp file
with open('/tmp/login_body.txt', 'w') as f:
    f.write(body)

r = subprocess.run(['curl', '-s', '-m', '10',
    'http://192.168.0.1/cgi_gdpr?8',
    '-H', 'X-Requested-With: XMLHttpRequest',
    '-H', 'Referer: http://192.168.0.1/',
    '-H', 'User-Agent: Mozilla/5.0',
    '-H', 'Accept: */*',
    '--data-binary', '@' + '/tmp/login_body.txt',
    '-c', '/tmp/cookies.txt', '-v'],
    capture_output=True, text=True, timeout=15)
print('Login curl stderr:', r.stderr[-300:] if r.stderr else '')
if r.stdout:
    print('Login response:', aes_decrypt(r.stdout.strip(), key, iv)[:100])
seq_int += dl

# Read JSESSIONID from cookie jar
jsid = None
if os.path.exists('/tmp/cookies.txt'):
    with open('/tmp/cookies.txt') as f:
        for line in f:
            if 'JSESSIONID' in line:
                parts = line.strip().split()
                if len(parts) >= 7:
                    jsid = parts[6]
                print('JSID from cookie file:', line.strip())

print('JSESSIONID:', jsid)

if jsid:
    # Query
    qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    enc2 = aes_encrypt(qb, key, iv)
    dl2 = len(enc2)
    sign_str2 = f'key={key}&iv={iv}&h={hsh}&s={seq_int + dl2}'
    se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
    body2 = f'sign={se2}\r\ndata={enc2}\r\n'
    
    with open('/tmp/query_body.txt', 'w') as f:
        f.write(body2)
    
    r2 = subprocess.run(['curl', '-s', '-m', '10',
        'http://192.168.0.1/cgi_gdpr?1',
        '-H', 'X-Requested-With: XMLHttpRequest',
        '-H', 'Referer: http://192.168.0.1/',
        '-H', 'User-Agent: Mozilla/5.0',
        '-H', 'Accept: */*',
        '-H', 'Cookie: JSESSIONID=' + jsid,
        '--data-binary', '@' + '/tmp/query_body.txt',
        '-v'],
        capture_output=True, text=True, timeout=15)
    print('Query curl stdout:', r2.stdout[:300] if r2.stdout else 'EMPTY')
    print('Query curl stderr:', r2.stderr[-500:] if r2.stderr else '')
    if r2.stdout:
        try:
            dec = aes_decrypt(r2.stdout.strip(), key, iv)
            print('Query decrypted:', dec[:500])
        except Exception as e:
            print('Decrypt error:', e)
