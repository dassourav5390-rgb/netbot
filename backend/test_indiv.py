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
    try:
        key = key_str.encode('utf-8')
        iv = iv_str.encode('utf-8')
        ct = base64.b64decode(ciphertext_b64)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(padded) + unpadder.finalize()).decode('utf-8')
    except Exception as e:
        return None

def login(client):
    nn, ee, seq_str = get_rsa_params(client)
    seq_int = int(seq_str)
    key = ''.join([str(random.randint(0,9)) for _ in range(16)])
    iv = ''.join([str(random.randint(0,9)) for _ in range(16)])
    hash_val = hashlib.md5(('admin' + 'Admin@123').encode('utf-8')).hexdigest()
    data_plain = '8\r\n' + '[/cgi/login#0,0,0,0,0,0#0,0,0,0,0,0]0,2\r\nusername=admin\r\npassword=Admin@123\r\n'
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
    jsid = resp.cookies.get('JSESSIONID')
    return jsid, key, iv

# Try individual queries, each with its own session
with httpx.Client(verify=False, timeout=15) as client:
    oids_to_test = [
        'LAN_WLAN',
        'LAN_WLAN_MULTISSID',
        'LAN_WLAN_MSSIDENTRY',
        'LAN_WLAN_ASSOC_DEV',
        'LAN_WLAN_AC',
        'LAN_WLAN_GUESTNET',
        'WAN_IP_CONN',
        'WAN_PPP_CONN',
        'LAN_IP_INTF',
        'LAN_HOST_CFG',
        'LAN_DHCP_COND_SRV_POOL',
        'LAN_DHCP_STATIC_ADDR',
        'LAN_HOST_ENTRY',
        'FIREWALL',
        'RULE',
        'WAN_IP_CONN_PORTMAPPING',
        'DMZ_HOST_CFG',
        'SYS_STATE',
        'ARP_ENTRY',
    ]

    for oid in oids_to_test:
        try:
            jsid, key, iv = login(client)
            resp = client.post('http://192.168.0.1/cgi?1', content='[' + oid + '#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n', headers={
                'X-Requested-With': 'XMLHttpRequest', 'Referer': 'http://192.168.0.1/',
                'Cookie': 'JSESSIONID=' + jsid
            })
            if resp.status_code == 200:
                txt = resp.text[:500]
                if txt.startswith('[error]'):
                    print('X ' + oid + ' -> ' + txt[:50])
                else:
                    print('\n--- ' + oid + ' ---')
                    print(txt)
            else:
                print('! ' + oid + ' -> HTTP ' + str(resp.status_code))
        except Exception as e:
            print('! ' + oid + ' -> ' + str(e)[:80])
