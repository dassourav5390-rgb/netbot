import httpx, hashlib, base64, random, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_asym, padding as rsa_padding
from cryptography.hazmat.backends import default_backend

def get_rsa_params(client):
    resp = client.get('http://192.168.0.1/cgi/getParm', headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'User-Agent': 'Mozilla/5.0'
    })
    nn = re.search(r'var nn="([^"]+)"', resp.text).group(1)
    ee = re.search(r'var ee="([^"]+)"', resp.text).group(1)
    seq = re.search(r'var seq="([^"]+)"', resp.text).group(1)
    return nn, ee, seq

def rsa_encrypt_bytes(data_bytes, nn_hex, ee_hex):
    n, e = int(nn_hex, 16), int(ee_hex, 16)
    pub_key = rsa_asym.RSAPublicNumbers(e, n).public_key(default_backend())
    chunk_size, key_bytes = 53, 64
    result = b''
    for i in range(0, len(data_bytes), chunk_size):
        ct = pub_key.encrypt(data_bytes[i:i+chunk_size], rsa_padding.PKCS1v15())
        if len(ct) < key_bytes:
            ct = b'\x00' * (key_bytes - len(ct)) + ct
        result += ct
    return result.hex()

def aes_encrypt(plaintext, key_str, iv_str):
    key = key_str.encode('utf-8')
    iv = iv_str.encode('utf-8')
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    return base64.b64encode(cipher.encryptor().update(padded) + cipher.encryptor().finalize()).decode('utf-8')

with httpx.Client(verify=False, timeout=20) as client:
    # Test 1: password only to /cgi?8
    for label, body, url_path in [
        ('pwd-only cgi?8', '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\npassword=Admin@123', '/cgi?8'),
        ('pwd+user cgi?8', '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123', '/cgi?8'),
        ('pwd-only gdpr', '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,1\r\npassword=Admin@123', '/cgi_gdpr?8'),
        ('pwd+user gdpr', '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123', '/cgi_gdpr?8'),
    ]:
        url = f'http://192.168.0.1{url_path}'
        resp = client.post(url, content=body, headers={
            'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
        })
        print(f'{label}: status={resp.status_code}, resp={resp.text[:120]}, JSESSIONID={resp.cookies.get("JSESSIONID", "none")}')

    # Test 2: Encrypted flow matching browser exactly
    print('\n=== Encrypted flow ===')
    nn, ee, seq = get_rsa_params(client)
    print(f'seq={seq}')

    username = 'admin'
    password = 'Admin@123'
    key = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
    hash_val = hashlib.md5((username + password).encode('utf-8')).hexdigest()

    # Build the data exactly as the browser does:
    # tmpdata = "8" then data = "[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=xxx\r\npassword=xxx\r\n"
    data_plain = "8\r\n" + "[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=" + username + "\r\npassword=" + password + "\r\n"
    
    # AES encrypt the full data with flag=1 (includes key/iv in sign)
    data_enc = aes_encrypt(data_plain, key, iv)
    data_len = len(data_enc)
    seq_with_len = seq + str(data_len)
    sign_str = f"key={key}&iv={iv}&h={hash_val}&s={seq_with_len}"
    sign_enc = rsa_encrypt_bytes(sign_str.encode('utf-8'), nn, ee)

    enc_body = f"sign={sign_enc}\r\ndata={data_enc}\r\n"
    resp = client.post('http://192.168.0.1/cgi_gdpr?8', content=enc_body, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })
    print(f'encrypted: status={resp.status_code}, resp={resp.text[:200]}')
    print(f'JSESSIONID={resp.cookies.get("JSESSIONID", "none")}')
    print(f'Set-Cookie header: {resp.headers.get("set-cookie", "none")}')
