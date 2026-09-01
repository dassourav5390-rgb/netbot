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

def make_post(c, url, plaintext, cur_seq, key, iv, hsh, nn, ee, is_login, jsid=''):
    enc = aes_encrypt(plaintext, key, iv)
    dl = len(enc)
    sign_str = f'key={key}&iv={iv}&h={hsh}&s={cur_seq + dl}'
    se = rsa_encrypt_bytes(sign_str.encode(), nn, ee)
    body = f'sign={se}\r\ndata={enc}\r\n'
    hdrs = {
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'
    }
    if not is_login:
        hdrs['Cookie'] = 'JSESSIONID=' + jsid
    return c.post(url, content=body, headers=hdrs, timeout=15), cur_seq + dl

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

    # Login
    lb = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    r, seq_int = make_post(c, 'http://192.168.0.1/cgi_gdpr?8', lb, seq_int, key, iv, hsh, nn, ee, True)
    jsid = r.cookies.get('JSESSIONID')
    print(f'Login: {r.status_code} JSID={jsid}')
    if r.text:
        print('Decrypted:', aes_decrypt(r.text, key, iv)[:100])

    # Test 1: ACT_GET=1 with IGD_DEV_INFO (0 attrs)
    print('\n--- Test 1: ACT_GET=1 IGD_DEV_INFO ---')
    qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    try:
        r, seq_int = make_post(c, 'http://192.168.0.1/cgi_gdpr?1', qb, seq_int, key, iv, hsh, nn, ee, False, jsid)
        print(f'Result: {r.status_code}')
        if r.text:
            print('Decrypted:', aes_decrypt(r.text, key, iv)[:300])
    except Exception as e:
        print(f'CRASH: {e}')

    # Test 2: ACT_GET=1 with different body format (no trailing \r\n)
    print('\n--- Test 2: ACT_GET=1 IGD_DEV_INFO (no trailing) ---')
    qb2 = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0'
    try:
        r, seq_int = make_post(c, 'http://192.168.0.1/cgi_gdpr?1', qb2, seq_int, key, iv, hsh, nn, ee, False, jsid)
        print(f'Result: {r.status_code}')
        if r.text:
            print('Decrypted:', aes_decrypt(r.text, key, iv)[:300])
    except Exception as e:
        print(f'CRASH: {e}')
