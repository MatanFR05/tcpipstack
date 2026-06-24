from dataclasses import dataclass
from layer2 import Layer2Packet
import socket
import struct


@dataclass
class Ipv4Packet:
    version: int
    ihl: int  # Internet Header Length
    tos: int  # Type of Service
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int  # Time to Live
    protocol: int
    header_checksum: int
    source_ip: str
    destination_ip: str

    @staticmethod
    def is_ipv4(packet: Layer2Packet) -> bool:
        return Layer2Packet.parse_layer_2(packet).eth_type == 2048
    
    @staticmethod
    def parse_ipv4(packet_network_data: bytes) -> 'Ipv4Packet':
        ipv4_header = packet_network_data[:20]
        
        ipv4_struct = struct.unpack('!BBHHHBBH4s4s', ipv4_header)
        
        version_ihl = ipv4_struct[0]
        tos = ipv4_struct[1]
        total_length = ipv4_struct[2]
        identification = ipv4_struct[3]
        flags_fragment_offset = ipv4_struct[4]
        ttl = ipv4_struct[5]
        protocol = ipv4_struct[6]
        header_checksum = ipv4_struct[7]
        source_ip_raw = ipv4_struct[8]
        dest_ip_raw = ipv4_struct[9]

        # Extract Version (first 4 bits) and IHL (last 4 bits) from the first byte
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        # Extract Flags (first 3 bits) and Fragment Offset (last 13 bits)
        flags = flags_fragment_offset >> 13
        fragment_offset = flags_fragment_offset & 0x1FFF
        
        # Convert raw 4-byte IP addresses to readable strings (e.g., '192.168.1.1')
        source_ip_str = socket.inet_ntoa(source_ip_raw)
        dest_ip_str = socket.inet_ntoa(dest_ip_raw)
        
        return Ipv4Packet(
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            header_checksum=header_checksum,
            source_ip=source_ip_str,
            destination_ip=dest_ip_str
        )
