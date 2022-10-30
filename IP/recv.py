# Rohit

from binascii import hexlify
import socket
import struct


ip_proto = socket.htons(0x0800)
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ip_proto)
pkt = sock.recvfrom(2048)[0]

raw_ip_header = pkt[18:34]
print(hexlify(raw_ip_header))

row_2 = raw_ip_header[:2]
id = struct.unpack("!2s", row_2)
print(hexlify(id[0]))
