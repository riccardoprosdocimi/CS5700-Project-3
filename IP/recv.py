# Rohit

import socket


def get_nw_interface_name() -> str:
    prefixes = ("enp", "eth")

    for _, int_name in socket.if_nameindex():
        for prefix in prefixes:
            if int_name.startswith(prefix):
                return int_name

    raise ValueError("Cannot find a valid network interface")


ip_proto = socket.htons(0x0800)
sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, ip_proto)
pkt = sock.recvfrom(2048)
print(pkt)
