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

def aes_encrypt(p, k, iv):
    key = k.encode('utf-8'); ivs = iv.encode('utf-8')
    pad = padding.PKCS7(128).padder()
    padded = pad.update(p.encode('utf-8')) + pad.finalize()
    c = Cipher(algorithms.AES(key), modes.CBC(ivs), default_backend())
    return base64.b64encode(c.encryptor().update(padded) + c.encryptor().finalize()).decode('utf-8')

def aes_decrypt(ct_b64, k, iv):
    try:
        key = k.encode('utf-8'); ivs = iv.encode('utf-8')
        ct = base64.b64decode(ct_b64)
        c = Cipher(algorithms.AES(key), modes.CBC(ivs), default_backend())
        d = c.decryptor()
        p = padding.PKCS7(128).unpadder()
        return (p.update(d.update(ct) + d.finalize()) + p.finalize()).decode('utf-8')
    except:
        return None

def login(client):
    nn, ee, s = get_rsa_params(client)
    si = int(s)
    key = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
    h = hashlib.md5(('admin' + 'Admin@123').encode('utf-8')).hexdigest()
    dp = '8\r\n' + '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    de = aes_encrypt(dp, key, iv)
    swl = si + len(de)
    aks = 'key=' + key + '&iv=' + iv
    ss = aks + '&h=' + h + '&s=' + str(swl)
    se = rsa_encrypt_bytes(ss.encode('utf-8'), nn, ee)
    eb = 'sign=' + se + '\r\ndata=' + de + '\r\n'
    r = client.post('http://192.168.0.1/cgi_gdpr?8', content=eb, headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })
    return r.cookies.get('JSESSIONID'), key, iv

with httpx.Client(verify=False, timeout=15) as c:
    jsid, key, iv = login(c)
    print('JSESSIONID:', jsid)

    # Fetch status page
    r = c.get('http://192.168.0.1/main/status.htm', headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
        'Cookie': 'JSESSIONID=' + jsid
    })
    html = r.text
    print('Status page length:', len(html))

    # Save to file for analysis
    with open('/tmp/status.html', 'w', encoding='utf-8') as f:
        f.write(html)
    print('Saved to /tmp/status.html')

    # Find lines containing SSID, password, WAN, DHCP, etc.
    keywords = ['SSID', 'password', 'WAN', 'DHCP', 'wireless', ' Wireless', 'key_passphrase', 'PreSharedKey', 'enable', 'channel']
    for kw in keywords:
        lines = [l.strip() for l in html.split('\n') if kw.lower() in l.lower()]
        if lines:
            for l in lines[:5]:
                print(kw + ':', l[:200])
