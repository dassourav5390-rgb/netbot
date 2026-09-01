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

class Encryptor:
    def __init__(self):
        self.key = ''.join([str(random.randint(0,9)) for _ in range(16)])
        self.iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
        self.hash = hashlib.md5(('admin' + 'Admin@123').encode('utf-8')).hexdigest()
        self.seq = 0
        self.nn = None
        self.ee = None

    def set_seq(self, s):
        self.seq = int(s)

    def set_rsa(self, nn, ee):
        self.nn = nn
        self.ee = ee

    def encrypt_data(self, plaintext, is_login=False):
        data_enc = aes_encrypt(plaintext, self.key, self.iv)
        data_len = len(data_enc)
        if is_login:
            aks = 'key=' + self.key + '&iv=' + self.iv
            sign_str = aks + '&h=' + self.hash + '&s=' + str(self.seq + data_len)
        else:
            sign_str = 'h=' + self.hash + '&s=' + str(self.seq + data_len)
        sign_enc = rsa_encrypt_bytes(sign_str.encode('utf-8'), self.nn, self.ee)
        return 'sign=' + sign_enc + '\r\ndata=' + data_enc + '\r\n'

    def decrypt_response(self, ct_b64):
        return aes_decrypt(ct_b64, self.key, self.iv)

with httpx.Client(verify=False, timeout=15) as c:
    nn, ee, seq_str = get_rsa_params(c)
    enc = Encryptor()
    enc.set_seq(seq_str)
    enc.set_rsa(nn, ee)

    # Login
    login_body = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
    r = c.post('http://192.168.0.1/cgi_gdpr?8', content=enc.encrypt_data(login_body, is_login=True), headers={
        'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
    })
    jsid = r.cookies.get('JSESSIONID')
    print('JSESSIONID:', jsid)

    # Use ACT_GL (type=5) to list WLAN instances
    # Build: 5\r\n[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n
    def encrypted_query(client, cgi_type, oid_part, jsid):
        data_plain = str(cgi_type) + '\r\n[' + oid_part + '\r\n'
        r = client.post('http://192.168.0.1/cgi_gdpr?' + str(cgi_type), 
            content=enc.encrypt_data(data_plain, is_login=False), headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
                'Cookie': 'JSESSIONID=' + jsid
            })
        if r.status_code == 200:
            return enc.decrypt_response(r.text)
        return None

    # List WLAN instances (ACT_GL = 5)
    result = encrypted_query(c, 5, 'LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,12\r\nstatus\r\nSSID\r\nBSSID\r\nchannel\r\nstandard\r\nbeaconType\r\nbasicEncryptionModes\r\nX_TP_Bandwidth\r\nWPAAuthenticationMode\r\nIEEE11iAuthenticationMode\r\nX_TP_HWAccel\r\nenable', jsid)
    print('\n=== WLAN List (ACT_GL) ===')
    print(result[:1000] if result else 'FAILED')

    # Also try ACT_GL for WAN
    result2 = encrypted_query(c, 5, 'WAN_IP_CONN#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n', jsid)
    print('\n=== WAN_IP_CONN List ===')
    print(result2[:1000] if result2 else 'FAILED')

    # Try ACT_GS for DHCP leases
    result3 = encrypted_query(c, 6, 'LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n', jsid)
    print('\n=== LAN_HOST_ENTRY (ACT_GS) ===')
    print(result3[:1000] if result3 else 'FAILED')

    # Try ACT_GS for ARP
    result4 = encrypted_query(c, 6, 'ARP_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n', jsid)
    print('\n=== ARP_ENTRY (ACT_GS) ===')
    print(result4[:1000] if result4 else 'FAILED')
