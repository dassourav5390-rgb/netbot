import httpx, hashlib, base64, random, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_asym, padding as rsa_padding_mod
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
        ct = pub_key.encrypt(data_bytes[i:i+chunk_size], rsa_padding_mod.PKCS1v15())
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

def aes_decrypt(ciphertext_b64, key_str, iv_str):
    key = key_str.encode('utf-8')
    iv = iv_str.encode('utf-8')
    ct = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')

def login(client, username, password):
    """Perform full encrypted login, returns (success, jsessionid, keys_dict)"""
    nn, ee, seq_str = get_rsa_params(client)
    seq_int = int(seq_str)

    key = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
    hash_val = hashlib.md5((username + password).encode('utf-8')).hexdigest()

    data_plain = '8\r\n' + '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=' + username + '\r\npassword=' + password + '\r\n'
    data_enc = aes_encrypt(data_plain, key, iv)
    data_len = len(data_enc)
    seq_with_len = seq_int + data_len
    aes_key_string = 'key=' + key + '&iv=' + iv
    sign_str = aes_key_string + '&h=' + hash_val + '&s=' + str(seq_with_len)
    sign_enc = rsa_encrypt_bytes(sign_str.encode('utf-8'), nn, ee)

    enc_body = 'sign=' + sign_enc + '\r\ndata=' + data_enc + '\r\n'
    resp = client.post('http://192.168.0.1/cgi_gdpr?8', content=enc_body, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })

    jsessionid = resp.cookies.get('JSESSIONID', None)
    if jsessionid:
        # Decrypt the response
        try:
            plain = aes_decrypt(resp.text, key, iv)
            print('Login response (decrypted):', plain[:200])
            return True, jsessionid, {'key': key, 'iv': iv, 'nn': nn, 'ee': ee, 'seq': seq_int}
        except Exception as e:
            print('Failed to decrypt response:', e)
            print('Raw response:', resp.text[:200])
            return True, jsessionid, {'key': key, 'iv': iv, 'nn': nn, 'ee': ee, 'seq': seq_int}
    else:
        print('Login failed:', resp.text[:200])
        return False, None, None

with httpx.Client(verify=False, timeout=20) as client:
    success, jsid, keys = login(client, 'admin', 'Admin@123')
    if success:
        print('JSESSIONID:', jsid)
    else:
        print('Login FAILED')
