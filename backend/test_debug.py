import httpx, hashlib, base64, random, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa as rsa_asym, padding as rsa_padding_mod
from cryptography.hazmat.backends import default_backend

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

def aes_encrypt(p, k, iv):
    key = k.encode('utf-8'); ivs = iv.encode('utf-8')
    pad = padding.PKCS7(128).padder()
    padded = pad.update(p.encode('utf-8')) + pad.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(ivs), default_backend())
    return base64.b64encode(c.encryptor().update(padded) + c.encryptor().finalize()).decode('utf-8')

def aes_decrypt(ct_b64, k, iv):
    key = k.encode('utf-8'); ivs = iv.encode('utf-8')
    ct = base64.b64decode(ct_b64)
    c = Cipher(algorithms.AES(key), modes.CBC(ivs), default_backend())
    d = c.decryptor()
    p = padding.PKCS7(128).unpadder()
    return (p.update(d.update(ct) + d.finalize()) + p.finalize()).decode('utf-8')

base_headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
}
login_ref = 'http://192.168.0.1/'

with httpx.Client(verify=False, timeout=20) as c:
    # 1. Get RSA params
    r = c.get('http://192.168.0.1/cgi/getParm', headers={**base_headers, 'X-Requested-With': 'XMLHttpRequest', 'Referer': login_ref})
    nn = re.search(r'var nn="([^"]+)"', r.text).group(1)
    ee = re.search(r'var ee="([^"]+)"', r.text).group(1)
    seq = re.search(r'var seq="([^"]+)"', r.text).group(1)
    seq_int = int(seq)
    print(f'getParm OK, seq={seq[:20]}...')

    # 2. Generate encryptor params
    key = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
    hsh = hashlib.md5(('admin' + 'Admin@123').encode('utf-8')).hexdigest()
    print(f'key={key}, iv={iv}, hash={hsh}')

    # 3. Login
    login_body = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    login_enc = aes_encrypt(login_body, key, iv)
    data_len = len(login_enc)
    sign_str = 'key=' + key + '&iv=' + iv + '&h=' + hsh + '&s=' + str(seq_int + data_len)
    sign_enc = rsa_encrypt_bytes(sign_str.encode('utf-8'), nn, ee)
    post_body = 'sign=' + sign_enc + '\r\ndata=' + login_enc + '\r\n'
    
    r = c.post('http://192.168.0.1/cgi_gdpr?8', content=post_body, headers={
        **base_headers, 'X-Requested-With': 'XMLHttpRequest', 'Referer': login_ref, 'Origin': 'http://192.168.0.1'
    })
    print(f'Login status={r.status_code}, cookies={dict(r.cookies)}')
    print(f'Login headers: {dict(r.headers)}')
    dec = aes_decrypt(r.text, key, iv) if r.text else None
    print(f'Login decrypted: [{dec}]')

    jsid = r.cookies.get('JSESSIONID')
    if not jsid:
        # Try to get from Set-Cookie header
        for k, v in r.headers.items():
            if k.lower() == 'set-cookie':
                print(f'Set-Cookie: {v}')
                m = re.search(r'JSESSIONID=([^;]+)', v)
                if m:
                    jsid = m.group(1)
    print(f'JSESSIONID: {jsid}')

    if not jsid:
        print('No JSESSIONID!')
        exit()

    # 4. First data query - DHCP leases (ACT_GS=6) - simple test
    seq_int = seq_int + data_len
    print(f'\nSeq for query: {seq_int}')

    query_body = '6\r\n[LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,8\r\nleaseIP\r\nleaseMAC\r\nhostName\r\n'
    query_enc = aes_encrypt(query_body, key, iv)
    q_data_len = len(query_enc)
    sign_str2 = 'key=' + key + '&iv=' + iv + '&h=' + hsh + '&s=' + str(seq_int + q_data_len)
    sign_enc2 = rsa_encrypt_bytes(sign_str2.encode('utf-8'), nn, ee)
    post_body2 = 'sign=' + sign_enc2 + '\r\ndata=' + query_enc + '\r\n'
    
    print(f'Query body: {repr(query_body[:80])}...')
    print(f'Query enc: {query_enc[:50]}...')
    print(f'Sign str: {sign_str2}')
    
    r2 = c.post('http://192.168.0.1/cgi_gdpr?6', content=post_body2, headers={
        **base_headers, 'X-Requested-With': 'XMLHttpRequest', 'Referer': login_ref,
        'Cookie': 'JSESSIONID=' + jsid
    })
    print(f'Query status={r2.status_code}')
    if r2.status_code == 200 and r2.text:
        dec2 = aes_decrypt(r2.text, key, iv)
        print(f'Query decrypted: [{dec2[:500]}]')
    else:
        print(f'Query error: status={r2.status_code}, text={r2.text[:200] if r2.text else "None"}')

    # 5. Also try accessing status page
    r3 = c.get('http://192.168.0.1/main/status.htm', headers={
        **base_headers, 'Referer': login_ref, 'Cookie': 'JSESSIONID=' + jsid
    })
    print(f'\nStatus page: status={r3.status_code}, len={len(r3.text) if r3.text else 0}')
