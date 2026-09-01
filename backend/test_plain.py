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
    # Login via encrypted CGI
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
    print('JSID:', jsid)
    _ = r.text

    # Test plain CGI with JSESSIONID (no encryption)
    # URL format from lib.js non-encrypted: /cgi?1&oid=IGD_DEV_INFO
    print('\n--- Plain CGI GET with ?1 param ---')
    try:
        r = c.get('http://192.168.0.1/cgi?1', params={'oid': 'IGD_DEV_INFO'}, headers={
            'User-Agent': 'Mozilla/5.0', 'Referer': 'http://192.168.0.1/',
            'Cookie': 'JSESSIONID=' + jsid
        })
        print(f'Status: {r.status_code}')
        if r.text:
            print(f'Response: {r.text[:500]}')
    except Exception as e:
        print(f'Error: {e}')

    # Test plain CGI POST with data like lib.js non-encrypted does
    print('\n--- Plain CGI POST (like lib.js without encryption) ---')
    body_data = ''
    body_data += '1'  # type param
    body_data += '\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    try:
        r = c.post('http://192.168.0.1/cgi?1', content=body_data, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Content-Type': 'text/plain',
            'Cookie': 'JSESSIONID=' + jsid
        })
        print(f'Status: {r.status_code}')
        if r.text:
            print(f'Response: {r.text[:500]}')
    except Exception as e:
        print(f'Error: {e}')

    # Check if login also works with the same sequence
    print('\n--- Encrypted query to /cgi_gdpr?8 with non-login body ---')
    qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    enc2 = aes_encrypt(qb, key, iv)
    dl2 = len(enc2)
    sign_str2 = f'h={hsh}&s={seq_int + dl2}'  # NO seq update after login
    se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
    body2 = f'sign={se2}\r\ndata={enc2}\r\n'
    try:
        r2 = c.post('http://192.168.0.1/cgi_gdpr?8', content=body2, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
        })
        print(f'Status: {r2.status_code}')
        if r2.status_code == 200 and r2.text and len(r2.text) > 50:
            print('Decrypted:', aes_decrypt(r2.text, key, iv)[:500])
        elif r2.text:
            print(f'Response: {r2.text[:300]}')
    except Exception as e:
        print(f'Error: {e}')
