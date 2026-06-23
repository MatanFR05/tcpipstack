import socket
import struct
from dataclasses import dataclass
import uuid


@dataclass
class Layer2Packet:
    dest_mac: str
    src_mac: str
    eth_type: int
    data: bytes


@dataclass
class ArpPacket:
    hardware_type: int
    protocol_type: int
    hardware_length: int
    protocol_length: int
    operation: int
    sender_hardware_addr: str
    sender_protocol_addr: str
    target_hardware_addr: str
    target_protocol_addr: str


def is_arp(packet: Layer2Packet) -> bool:
    return parse_layer_2(packet).eth_type == 2054


def parse_layer_2(packet_with_layer_2_heaer: bytes) -> Layer2Packet:
    eth_header_bytes = packet_with_layer_2_heaer[:14]
    dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', eth_header_bytes)
    return Layer2Packet(dest_mac, src_mac, eth_type, packet_with_layer_2_heaer[14:])


def unparse_layer_2(layer2_packet: Layer2Packet) -> bytes:
    dest_mac_bytes = bytes.fromhex(layer2_packet.dest_mac.replace(':', ''))
    src_mac_bytes = bytes.fromhex(layer2_packet.src_mac.replace(':', ''))
    eth_header_bytes = struct.pack(
        '!6s6sH', 
        dest_mac_bytes, 
        src_mac_bytes, 
        layer2_packet.eth_type
    )
    return eth_header_bytes + layer2_packet.data


def is_arp_request(packet: ArpPacket) -> bool:
    return parse_arp(packet).operation == 1


def get_my_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip = s.getsockname()[0]
    s.close()
    return ip

def should_reply(packet: bytes) -> bool:
    return parse_arp(packet).target_protocol_addr == get_my_ip()

def parse_arp(packet_layer_2_data: bytes) -> ArpPacket:
    arp_struct = struct.unpack('!HHBBH6s4s6s4s', packet_layer_2_data[:28])
    
    hw_type, proto_type, hw_len, proto_len, operation, sha, spa, tha, tpa = arp_struct
    
    sha_str = sha.hex(':')
    tha_str = tha.hex(':')
    spa_str = socket.inet_ntoa(spa)
    tpa_str = socket.inet_ntoa(tpa)
    
    return ArpPacket(
        hardware_type=hw_type,
        protocol_type=proto_type,
        hardware_length=hw_len,
        protocol_length=proto_len,
        operation=operation,
        sender_hardware_addr=sha_str,
        sender_protocol_addr=spa_str,
        target_hardware_addr=tha_str,
        target_protocol_addr=tpa_str
    )

def unparse_arp(packet_layer_2_data: ArpPacket) -> bytes:
    # 1. Convert MAC strings back to raw 6 bytes
    sha_bytes = bytes.fromhex(packet_layer_2_data.sender_hardware_addr.replace(':', ''))
    tha_bytes = bytes.fromhex(packet_layer_2_data.target_hardware_addr.replace(':', ''))
    
    # 2. Convert IP strings back to raw 4 bytes
    spa_bytes = socket.inet_aton(packet_layer_2_data.sender_protocol_addr)
    tpa_bytes = socket.inet_aton(packet_layer_2_data.target_protocol_addr)
    
    # 3. Use struct.pack to bake it into a single byte string
    arp_payload = struct.pack(
        '!HHBBH6s4s6s4s',
        packet_layer_2_data.hardware_type,
        packet_layer_2_data.protocol_type,
        packet_layer_2_data.hardware_length,
        packet_layer_2_data.protocol_length,
        packet_layer_2_data.operation,
        sha_bytes,
        spa_bytes,
        tha_bytes,
        tpa_bytes
    )
    
    return arp_payload


def arp_reply_layer_2(arp_request_packet: ArpPacket) -> None:
    arp_reply_packet = create_arp_reply(arp_request_packet)
    src_mac = arp_reply_packet.sender_hardware_addr
    dest_mac = arp_reply_packet.target_hardware_addr
    raw_arp_reply_packet = unparse_arp(arp_reply_packet)
    layer_2_packet = Layer2Packet(
        dest_mac=dest_mac,
        src_mac=src_mac,
        eth_type=2054,
        data=raw_arp_reply_packet
    )
    return unparse_layer_2(layer_2_packet)
    

def create_arp_reply(request_packet: ArpPacket) -> ArpPacket:
    #swaping sender and target addresses from the request, except sender_hardware_addr, which the request doesn't know and wants to find out
    #changing operation value to 2 which means reply
    #keeping the rest based on the request
    mac_int = uuid.getnode()
    my_mac_str = ':'.join(f'{(mac_int >> i) & 0xff:02x}' for i in range(40, -1, -8))
    return ArpPacket(
        hardware_type=request_packet.hardware_type,
        protocol_type=request_packet.protocol_type,
        hardware_length=request_packet.hardware_length,
        protocol_length=request_packet.protocol_length,
        operation=2,
        sender_hardware_addr=my_mac_str,
        sender_protocol_addr=request_packet.target_protocol_addr,
        target_hardware_addr=request_packet.sender_hardware_addr,
        target_protocol_addr=request_packet.sender_protocol_addr
    )


def main():
    print("check")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
    while True:
        data = s.recv(1024)
        print("this is the raw packet we received:")
        print(data)
        if is_arp(data):
            print("it's an arp")
            arp_packet_bytes = parse_layer_2(data).data
            if is_arp_request(arp_packet_bytes):
                print("it's an arp request!")
                if should_reply(arp_packet_bytes):
                    print("lets reply")                
                    parsed_arp_request = parse_arp(arp_packet_bytes)                                
                    raw_arp_reply_packet = arp_reply_layer_2(parsed_arp_request)                                    
                    s.sendto(raw_arp_reply_packet, ('eth0', 0))
                    print("the reply was successfully sent, and it is:")
                    print(raw_arp_reply_packet)                


main()