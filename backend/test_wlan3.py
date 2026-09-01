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
        self.nn = nn; self.ee = ee
    def encrypt_data(self, plaintext, is_login=False):
        data_enc = aes_encrypt(plaintext, self.key, self.iv)
        data_len = len(data_enc)
        if is_login:
            sign_str = 'key=' + self.key + '&iv=' + self.iv + '&h=' + self.hash + '&s=' + str(self.seq + data_len)
        else:
            sign_str = 'h=' + self.hash + '&s=' + str(self.seq + data_len)
        sign_enc = rsa_encrypt_bytes(sign_str.encode('utf-8'), self.nn, self.ee)
        self.seq = self.seq + data_len
        return 'sign=' + sign_enc + '\r\ndata=' + data_enc + '\r\n'
    def decrypt_response(self, ct_b64):
        return aes_decrypt(ct_b64, self.key, self.iv)

class RouterClient:
    def __init__(self):
        self.client = httpx.Client(verify=False, timeout=15)
        nn, ee, seq = get_rsa_params(self.client)
        self.enc = Encryptor()
        self.enc.set_seq(seq)
        self.enc.set_rsa(nn, ee)
        self.jsid = None

    def login(self, password='Admin@123'):
        body = '8\r\n[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=' + password + '\r\n'
        r = self.client.post('http://192.168.0.1/cgi_gdpr?8',
            content=self.enc.encrypt_data(body, is_login=True), headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/'
            })
        self.jsid = r.cookies.get('JSESSIONID')
        dec = self.enc.decrypt_response(r.text)
        print('Login JSID:', self.jsid, '| Response:', dec[:100] if dec else 'None')

    def q(self, cgi_type, oid_data):
        body = str(cgi_type) + '\r\n[' + oid_data.rstrip('\r\n') + '\r\n'
        r = self.client.post('http://192.168.0.1/cgi_gdpr?' + str(cgi_type),
            content=self.enc.encrypt_data(body, is_login=False), headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
                'Cookie': 'JSESSIONID=' + self.jsid
            })
        if r.status_code == 200 and r.text:
            return self.enc.decrypt_response(r.text)
        return None

rc = RouterClient()
rc.login()

# WLAN list ACT_GL
r = rc.q(5, 'LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,10\r\nstatus\r\nSSID\r\nBSSID\r\nchannel\r\nstandard\r\nbeaconType\r\nbasicEncryptionModes\r\nX_TP_Bandwidth\r\nWPAAuthenticationMode\r\nIEEE11iAuthenticationMode')
print('\nWLAN list:\n', r[:2000] if r else 'None')

r = rc.q(5, 'LAN_HOST_ENTRY#0,0,0,0,0,0#0,0,0,0,0,0]0,8\r\nleaseIP\r\nleaseMAC\r\nhostName')
print('\nDHCP leases:\n', r[:1000] if r else 'None')

r = rc.q(5, 'LAN_IP_INTF#0,0,0,0,0,0#0,0,0,0,0,0]0,4\r\nIPInterfaceIPAddress\r\nIPInterfaceSubnetMask\r\nX_TP_MACAddress\r\nX_TP_IPv4DHCPEnable')
print('\nLAN IP:\n', r[:500] if r else 'None')

r = rc.q(5, 'LAN_HOST_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,9\r\nenable\r\nX_TP_DHCPv4\r\nminAddress\r\nmaxAddress\r\nsubnetMask\r\nDNSServers\r\ndomainName\r\nIPRouters\r\nleaseTime')
print('\nDHCP cfg:\n', r[:500] if r else 'None')

# WLAN with passwords
r = rc.q(5, 'LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0,15\r\nstatus\r\nSSID\r\nBSSID\r\nchannel\r\nstandard\r\nbeaconType\r\nbasicEncryptionModes\r\nX_TP_Bandwidth\r\nWPAAuthenticationMode\r\nIEEE11iAuthenticationMode\r\nPreSharedKey\r\nkeyPassphrase\r\nX_TP_ExtKeyType\r\nWEPKey\r\nbasicAuthenticationMode')
print('\nWLAN w/ pwd:\n', r[:2000] if r else 'None')
