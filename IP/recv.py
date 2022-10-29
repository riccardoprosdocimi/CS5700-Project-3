# Rohit

import socket


ip_proto = socket.htons(0x0800)
sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, ip_proto)
pkt = sock.recvfrom(2048)
print(pkt)
