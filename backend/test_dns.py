import socket
try:
    socket.setdefaulttimeout(5)
    ip = socket.gethostbyname("api.telegram.org")
    print(f"DNS ok: {ip}")
except Exception as e:
    print(f"DNS fail: {e}")
