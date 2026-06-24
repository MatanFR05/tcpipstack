import socket

def get_my_ip() -> str: #TODO why connect?
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def iface_to_mac(iface: str) -> str: #TODO complete function
    pass
