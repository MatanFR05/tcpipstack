import socket
import struct
from dataclasses import dataclass
import uuid
from layer2 import Layer2Packet
from helper_functions import get_my_ip

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

    @staticmethod
    def is_arp(packet: Layer2Packet) -> bool:
        return Layer2Packet.parse_layer_2(packet).eth_type == 2054
    
    @staticmethod
    def parse_arp(packet_layer_2_data: bytes) -> 'ArpPacket':
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


    @staticmethod
    def is_arp_request(packet: 'ArpPacket') -> bool:
        return ArpPacket.parse_arp(packet).operation == 1

    @staticmethod
    def should_reply(packet: bytes) -> bool:
        return ArpPacket.parse_arp(packet).target_protocol_addr == get_my_ip()

    @staticmethod
    def unparse_arp(packet_layer_2_data: 'ArpPacket') -> bytes:
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



    def arp_reply_layer_2(self) -> None:
        arp_reply_packet = self.create_arp_reply()
        src_mac = arp_reply_packet.sender_hardware_addr
        dest_mac = arp_reply_packet.target_hardware_addr
        raw_arp_reply_packet = self.unparse_arp(arp_reply_packet)
        layer_2_packet = Layer2Packet(
            dest_mac=dest_mac,
            src_mac=src_mac,
            eth_type=2054,
            data=raw_arp_reply_packet
        )
        return Layer2Packet.unparse_layer_2(layer_2_packet)
        

    def create_arp_reply(self) -> 'ArpPacket':
        #swaping sender and target addresses from the request, except sender_hardware_addr, which the request doesn't know and wants to find out
        #changing operation value to 2 which means reply
        #keeping the rest based on the request
        mac_int = uuid.getnode()
        my_mac_str = ':'.join(f'{(mac_int >> i) & 0xff:02x}' for i in range(40, -1, -8))
        return ArpPacket(
            hardware_type=self.hardware_type,
            protocol_type=self.protocol_type,
            hardware_length=self.hardware_length,
            protocol_length=self.protocol_length,
            operation=2,
            sender_hardware_addr=my_mac_str,
            sender_protocol_addr=self.target_protocol_addr,
            target_hardware_addr=self.sender_hardware_addr,
            target_protocol_addr=self.sender_protocol_addr
        )
