import socket
import struct
from dataclasses import dataclass
import uuid
from layer2 import Layer2Packet
from arp import ArpPacket
from ipv4 import Ipv4Packet
from helper_functions import get_my_ip, iface_to_mac
from routing_table import *


print("check")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
while True:
    data = s.recv(1024)
    print("this is the raw packet we received:")
    print(data)
    if ArpPacket.is_arp(data):
        print("it's an arp")
        layer2_packet: Layer2Packet = Layer2Packet.parse_layer_2(data).data
        if ArpPacket.is_arp_request(layer2_packet):
            print("it's an arp request!")
            if ArpPacket.should_reply(layer2_packet):
                print("lets reply")                
                parsed_arp_request = ArpPacket.parse_arp(layer2_packet)                                
                raw_arp_reply_packet = parsed_arp_request.arp_reply_layer_2()
                s.sendto(raw_arp_reply_packet, ('eth0', 0))
                print("the reply was successfully sent, and it is:")
                print(raw_arp_reply_packet)  
        elif Ipv4Packet.is_ipv4(layer2_packet):      
            ipv4_packet = Ipv4Packet.parse_ipv4(layer2_packet)
            if ipv4_packet.destination_ip == get_my_ip():
                print(f"Thank you for the packet: {ipv4_packet.source_ip}")
            else:
                best_route = best_route(parse_routing_table_content(get_routing_table_content()), ipv4_packet.destination_ip)
                print(f"The ip of the next hop is: {best_route.dst}")
                layer2_packet.src_mac = iface_to_mac(best_route.iface)
                dst_ip = best_route.gateway if best_route.is_default_gateway else best_route.dst

