# Rohit

import socket


HOST = socket.gethostbyname(socket.gethostname())
print(HOST)
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
sock.bind((HOST, 0))
print(sock.recv(2048))
