import socket
from concurrent.futures import ThreadPoolExecutor


# 🔹 Scan single port
def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)   # ✅ better timeout

        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            return port

    except:
        pass

    return None


# 🔹 Resolve domain → IP
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except:
        return None


# 🔹 Main scanner
def scan_ports(target):

    ip = resolve_target(target)

    if not ip:
        return []   # invalid target safe handling

    open_ports = []

    ports = range(1, 5000)   # ✅ scan 1–5000 (correct + fast)

    # ⚡ Multi-threading
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports