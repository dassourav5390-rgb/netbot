import httpx, hashlib, base64, random, re
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

# Step 1: Get RSA params (fresh client)
with httpx.Client(verify=False, timeout=20) as c:
    r = c.get('http://192.168.0.1/cgi/getParm', headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0'
    })
    nn = re.search(r'var nn="([^"]+)"', r.text).group(1)
    ee = re.search(r'var ee="([^"]+)"', r.text).group(1)
    seq_int = int(re.search(r'var seq="([^"]+)"', r.text).group(1))
    print('Initial seq:', seq_int)

key = ''.join([str(random.randint(0,9)) for _ in range(16)])
iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
hsh = hashlib.md5(b'adminAdmin@123').hexdigest()

# Step 2: Login (fresh client)
with httpx.Client(verify=False, timeout=20) as c:
    lb = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    enc = aes_encrypt(lb, key, iv)
    dl = len(enc)
    sign_str = f'key={key}&iv={iv}&h={hsh}&s={seq_int + dl}'
    se = rsa_encrypt_bytes(sign_str.encode(), nn, ee)
    body = f'sign={se}\r\ndata={enc}\r\n'
    r = c.post('http://192.168.0.1/cgi_gdpr?8', content=body, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'
    })
    jsid = r.cookies.get('JSESSIONID')
    # Read response body fully
    _ = r.text
    print(f'Login: {r.status_code} JSID={jsid}')
    
    seq_int += dl

    # Step 3: Query (SAME client, connection reuse)
    print('\n--- Query with same httpx client ---')
    qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    enc2 = aes_encrypt(qb, key, iv)
    dl2 = len(enc2)
    sign_str2 = f'key={key}&iv={iv}&h={hsh}&s={seq_int + dl2}'
    se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
    body2 = f'sign={se2}\r\ndata={enc2}\r\n'
    try:
        r2 = c.post('http://192.168.0.1/cgi_gdpr?1', content=body2, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
        })
        print(f'Query: {r2.status_code}')
        if r2.text:
            print('Dec:', aes_decrypt(r2.text, key, iv)[:300])
    except Exception as e:
        print(f'SAME client: CRASH: {e}')

# Step 4: Login again, then query with FRESH client
print('\n--- Query with FRESH httpx client ---')
with httpx.Client(verify=False, timeout=20) as c:
    r3 = c.get('http://192.168.0.1/cgi/getParm', headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0'
    })
    nn2 = re.search(r'var nn="([^"]+)"', r3.text).group(1)
    ee2 = re.search(r'var ee="([^"]+)"', r3.text).group(1)
    seq2 = int(re.search(r'var seq="([^"]+)"', r3.text).group(1))
    
    key2 = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv2 = ''.join([str(random.randint(0,9)) for _ in range(16)])
    hsh2 = hashlib.md5(b'adminAdmin@123').hexdigest()
    
    # Login
    lb3 = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    enc3 = aes_encrypt(lb3, key2, iv2)
    dl3 = len(enc3)
    sign3 = f'key={key2}&iv={iv2}&h={hsh2}&s={seq2 + dl3}'
    se3 = rsa_encrypt_bytes(sign3.encode(), nn2, ee2)
    body3 = f'sign={se3}\r\ndata={enc3}\r\n'
    r3 = c.post('http://192.168.0.1/cgi_gdpr?8', content=body3, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'
    })
    jsid2 = r3.cookies.get('JSESSIONID')
    _ = r3.text
    print(f'Login2: {r3.status_code} JSID={jsid2}')
    seq2 += dl3
    
    # Query with FRESH client
    qb3 = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    enc4 = aes_encrypt(qb3, key2, iv2)
    dl4 = len(enc4)
    sign4 = f'key={key2}&iv={iv2}&h={hsh2}&s={seq2 + dl4}'
    se4 = rsa_encrypt_bytes(sign4.encode(), nn2, ee2)
    body4 = f'sign={se4}\r\ndata={enc4}\r\n'
    try:
        r4 = c.post('http://192.168.0.1/cgi_gdpr?1', content=body4, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid2
        })
        print(f'Query2: {r4.status_code}')
        if r4.text:
            print('Dec2:', aes_decrypt(r4.text, key2, iv2)[:300])
    except Exception as e:
        print(f'FRESH client: CRASH: {e}')
