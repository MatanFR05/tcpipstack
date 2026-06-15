import socket
import struct

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))


def parseLayer2(raw_buffer):
    eth_header_bytes = raw_buffer[:14]
    dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', eth_header_bytes)
    print(dest_mac)
    print(src_mac)
    print(eth_type)

parseLayer2(s.recv(1024))