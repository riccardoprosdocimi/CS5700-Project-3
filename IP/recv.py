# Rohit

import socket

from IP import IPPacket

ip_proto = socket.htons(0x0800)
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ip_proto)


def start():
    while True:
        raw_pkt = sock.recvfrom(4096)[0]
        ip_pkt = IPPacket.from_bytes(raw_pkt=raw_pkt)
        print(ip_pkt)
