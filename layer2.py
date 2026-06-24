from dataclasses import dataclass
import struct

@dataclass
class Layer2Packet:
    dest_mac: str
    src_mac: str
    eth_type: int
    data: bytes


    @staticmethod
    def parse_layer_2(packet_with_layer_2_heaer: bytes) -> 'Layer2Packet':
        eth_header_bytes = packet_with_layer_2_heaer[:14]
        dest_mac, src_mac, eth_type = struct.unpack('!6s6sH', eth_header_bytes)
        return Layer2Packet(dest_mac, src_mac, eth_type, packet_with_layer_2_heaer[14:])


    def unparse_layer_2(self) -> bytes:
        dest_mac_bytes = bytes.fromhex(self.dest_mac.replace(':', ''))
        src_mac_bytes = bytes.fromhex(self.src_mac.replace(':', ''))
        eth_header_bytes = struct.pack(
            '!6s6sH', 
            dest_mac_bytes, 
            src_mac_bytes, 
            self.eth_type
        )
        return eth_header_bytes + self.data
