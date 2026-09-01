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
    # Login
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
    seq_int += dl

    # The login CGI type is 8 (ACT_CGI). What if data queries also need type 8?
    print('\n--- Try using type=8 for data query ---')
    qb = '1\r\n[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
    enc2 = aes_encrypt(qb, key, iv)
    dl2 = len(enc2)
    sign_str2 = f'h={hsh}&s={seq_int + dl2}'
    se2 = rsa_encrypt_bytes(sign_str2.encode(), nn, ee)
    body2 = f'sign={se2}\r\ndata={enc2}\r\n'

    try:
        r2 = c.post('http://192.168.0.1/cgi_gdpr?8', content=body2, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
            'User-Agent': 'Mozilla/5.0', 'Accept': '*/*', 'Cookie': 'JSESSIONID=' + jsid
        })
        print(f'Status: {r2.status_code}')
        if r2.status_code == 200 and r2.text and len(r2.text) > 10:
            dec = aes_decrypt(r2.text, key, iv)
            print('Decrypted:', dec[:500])
        else:
            print('Response:', r2.text[:300] if r2.text else 'empty')
    except Exception as e:
        print(f'Error: {e}')

    # Also try accessing status page HTML to extract the actual lib.js
    r3 = c.get('http://192.168.0.1/main/status.htm', headers={
        'User-Agent': 'Mozilla/5.0', 'Referer': 'http://192.168.0.1/',
        'Cookie': 'JSESSIONID=' + jsid
    })
    if r3.status_code == 200:
        # Find script tags
        import re as re2
        scripts = re2.findall(r'<script[^>]*src="([^"]*\.js)"', r3.text)
        print('\nJS files:', scripts[:10])
        
        # Also find inline JS with function definitions
        for s in re2.findall(r'<script[^>]*>([^<]+)</script>', r3.text):
            if 'function' in s:
                # Look for act and exe functions
                if 'act' in s and 'exe' in s:
                    print('\nFound act/exe in inline script!')
                    lines = s.split(';')
                    for line in lines:
                        if 'act' in line.lower() or 'exe' in line.lower() or 'build' in line.lower() or 'encrypt' in line.lower():
                            print(line.strip()[:200])
