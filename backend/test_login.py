import httpx
import hashlib
import base64
import random
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
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

def rsa_encrypt_python(data_bytes, nn_hex, ee_hex):
    n, e = int(nn_hex, 16), int(ee_hex, 16)
    pub_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    chunk_size, key_bytes = 53, 64
    result = b''
    for i in range(0, len(data_bytes), chunk_size):
        ct = pub_key.encrypt(data_bytes[i:i+chunk_size], rsa_padding.PKCS1v15())
        if len(ct) < key_bytes:
            ct = b'\x00' * (key_bytes - len(ct)) + ct
        result += ct
    return result.hex()

def aes_encrypt(plaintext, key_str, iv_str):
    key, iv = key_str.encode('utf-8'), iv_str.encode('utf-8')
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    return base64.b64encode(cipher.encryptor().update(padded) + cipher.encryptor().finalize()).decode('utf-8')

with httpx.Client(verify=False, timeout=20) as client:
    nn, ee, seq = get_rsa_params(client)
    print('seq:', seq)

    username = 'admin'
    password = 'Admin@123'  # TRY YOUR REAL PASSWORD HERE

    # The correct format from exe function:
    # URL: /cgi?8
    # Body: [oid#stack#pStack]index,count\r\nattrs
    body_data = "[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=" + username + "\r\npassword=" + password

    print('=== Correct CGI format ===')
    resp = client.post('http://192.168.0.1/cgi?8', content=body_data, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })
    print('Status:', resp.status_code)
    print('Response:', resp.text)
    print('Set-Cookie:', resp.headers.get('set-cookie', 'none'))

    # Also try encrypted version
    print('\n=== Encrypted to /cgi?8 ===')
    key = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
    hash_val = hashlib.md5((username + password).encode('utf-8')).hexdigest()

    data_enc = aes_encrypt(body_data, key, iv)
    data_len = len(data_enc)

    seq_with_len = seq + str(data_len)
    sign_str = f"key={key}&iv={iv}&h={hash_val}&s={seq_with_len}"
    sign_enc = rsa_encrypt_python(sign_str.encode('utf-8'), nn, ee)

    encrypted_body = f"sign={sign_enc}\r\ndata={data_enc}\r\n"
    resp = client.post('http://192.168.0.1/cgi?8', content=encrypted_body, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })
    print('Status:', resp.status_code)
    print('Response:', resp.text)
    print('Set-Cookie:', resp.headers.get('set-cookie', 'none'))

    # Try with the stack/pStack with fewer zeros
    print('\n=== Simpler stack format ===')
    body2 = "[/cgi/login]0,2\r\nusername=" + username + "\r\npassword=" + password
    resp = client.post('http://192.168.0.1/cgi?8', content=body2, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })
    print('Status:', resp.status_code)
    print('Response:', resp.text)
    print('Set-Cookie:', resp.headers.get('set-cookie', 'none'))
