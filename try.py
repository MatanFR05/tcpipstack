import socket
import struct
from dataclasses import dataclass
import uuid
from layer2 import Layer2Packet
from arp import ArpPacket


print("check")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
while True:
    data = s.recv(1024)
    print("this is the raw packet we received:")
    print(data)
    if ArpPacket.is_arp(data):
        print("it's an arp")
        arp_packet_bytes = Layer2Packet.parse_layer_2(data).data
        if ArpPacket.is_arp_request(arp_packet_bytes):
            print("it's an arp request!")
            if ArpPacket.should_reply(arp_packet_bytes):
                print("lets reply")                
                parsed_arp_request = ArpPacket.parse_arp(arp_packet_bytes)                                
                raw_arp_reply_packet = parsed_arp_request.arp_reply_layer_2()
                s.sendto(raw_arp_reply_packet, ('eth0', 0))
                print("the reply was successfully sent, and it is:")
                print(raw_arp_reply_packet)                

