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
    r = c.post('http://192.168.0.1/cgi_gdpr?8', content=pb, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'
    })
    jsid = r.cookies.get('JSESSIONID')
    if not jsid:
        import re as re2
        m = re2.search(r'JSESSIONID=([^;]+)', str(r.headers))
        jsid = m.group(1) if m else None
    print('Login JSID:', jsid)
    dec = aes_decrypt(r.text, key, iv)
    print('Login response:', dec[:100])

    if not jsid:
        exit(1)

    # TEST 1: Use ORIGINAL seq (no update after login) - like original working test
    print('\n--- TEST 1: original seq (no post-login update) ---')
    qb = '6\r\n[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,8\r\nleaseIP\r\nleaseMAC\r\nhostName\r\n'
    qe = aes_encrypt(qb, key, iv)
    qdl = len(qe)
    # Use initial seq (NOT updated after login)
    test_seq = seq_int  # initial, NOT seq_int + dl
    ss2 = f'h={hsh}&s={test_seq + qdl}'
    se2 = rsa_encrypt_bytes(ss2.encode(), nn, ee)
    pb2 = f'sign={se2}\r\ndata={qe}\r\n'
    print(f'  seq used: {test_seq + qdl}')
    try:
        r2 = c.post('http://192.168.0.1/cgi_gdpr?6', content=pb2, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
        })
        if r2.status_code == 200 and r2.text:
            dec2 = aes_decrypt(r2.text, key, iv)
            print(f'  Response: {dec2[:500]}')
        else:
            print(f'  Error: status={r2.status_code}, text={r2.text[:100]}')
    except Exception as e:
        print(f'  CRASH: {e}')

    if jsid:
        # TEST 2: Use UPDATED seq (seq_int + dl) - like JS behavior
        print('\n--- TEST 2: updated seq (post-login update) ---')
        qb2 = '6\r\n[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,8\r\nleaseIP\r\nleaseMAC\r\nhostName\r\n'
        qe2 = aes_encrypt(qb2, key, iv)
        qdl2 = len(qe2)
        test_seq2 = seq_int + dl  # updated after login
        ss3 = f'h={hsh}&s={test_seq2 + qdl2}'
        se3 = rsa_encrypt_bytes(ss3.encode(), nn, ee)
        pb3 = f'sign={se3}\r\ndata={qe2}\r\n'
        print(f'  seq used: {test_seq2 + qdl2}')
        try:
            r3 = c.post('http://192.168.0.1/cgi_gdpr?6', content=pb3, headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
                'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
            })
            if r3.status_code == 200 and r3.text:
                dec3 = aes_decrypt(r3.text, key, iv)
                print(f'  Response: {dec3[:500]}')
            else:
                print(f'  Error: status={r3.status_code}, text={r3.text[:100]}')
        except Exception as e:
            print(f'  CRASH: {e}')
