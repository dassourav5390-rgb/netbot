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

    def encrypt_and_post(url, plaintext, seq, is_login, cookie=''):
        enc = aes_encrypt(plaintext, key, iv)
        dl = len(enc)
        if is_login:
            sign = f'key={key}&iv={iv}&h={hsh}&s={seq + dl}'
        else:
            sign = f'h={hsh}&s={seq + dl}'
        se = rsa_encrypt_bytes(sign.encode(), nn, ee)
        body = f'sign={se}\r\ndata={enc}\r\n'
        hdrs = {
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'
        }
        if cookie:
            hdrs['Cookie'] = 'JSESSIONID=' + cookie
        try:
            r = c.post(url, content=body, headers=hdrs, timeout=15)
            return ('OK', r.status_code, r.text, seq + dl)
        except Exception as e:
            return ('CRASH', 0, str(e), seq)

    # Login
    lb = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    status, code, text, seq_int = encrypt_and_post('http://192.168.0.1/cgi_gdpr?8', lb, seq_int, True)
    jsid = c.cookies.get('JSESSIONID')
    print(f'Login: {status} code={code} JSID={jsid}')
    if text:
        print('Decrypted:', aes_decrypt(text, key, iv)[:80])

    # Test 1: URL = /cgi_gdpr? (no type, like lib.js does)
    # Use ORIGINAL seq (before login update) - like old working test
    original_seq = seq_int - len(aes_encrypt('8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n', key, iv))
    print(f'\nOriginal seq: {original_seq}, Current seq: {seq_int}')
    
    print('\n--- Test 1: Using ORIGINAL seq (like old working test) ---')
    qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    # Use original_seq instead of seq_int
    enc = aes_encrypt(qb, key, iv)
    dl = len(enc)
    sign = f'h={hsh}&s={original_seq + dl}'
    se = rsa_encrypt_bytes(sign.encode(), nn, ee)
    body = f'sign={se}\r\ndata={enc}\r\n'
    try:
        r = c.post('http://192.168.0.1/cgi_gdpr?', content=body, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
        }, timeout=15)
        print(f'Result: {r.status_code}')
        if r.status_code == 200 and r.text and len(r.text) > 50:
            print('Decrypted:', aes_decrypt(r.text, key, iv)[:500])
        elif r.text:
            print('Response:', r.text[:300])
    except Exception as e:
        print(f'Error: {e}')
    
    # Test 2: Same but with ?1 in URL
    print('\n--- Test 2: Using ORIGINAL seq with ?1 URL ---')
    enc2 = aes_encrypt(qb, key, iv)
    dl2 = len(enc2)
    sign2 = f'h={hsh}&s={original_seq + dl2}'
    se2 = rsa_encrypt_bytes(sign2.encode(), nn, ee)
    body2 = f'sign={se2}\r\ndata={enc2}\r\n'
    try:
        r2 = c.post('http://192.168.0.1/cgi_gdpr?1', content=body2, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
        }, timeout=15)
        print(f'Result: {r2.status_code}')
        if r2.status_code == 200 and r2.text and len(r2.text) > 50:
            print('Decrypted:', aes_decrypt(r2.text, key, iv)[:500])
        elif r2.text:
            print('Response:', r2.text[:300])
    except Exception as e:
        print(f'Error: {e}')
