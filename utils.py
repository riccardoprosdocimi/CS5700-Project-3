import socket
import struct


def get_nw_interface_name() -> str:
    prefixes = ("enp", "eth", "wlp")

    for _, int_name in socket.if_nameindex():
        for prefix in prefixes:
            if int_name.startswith(prefix):
                return int_name

    raise ValueError("Cannot find a valid network interface")


def get_local_ip():
    from subprocess import check_output
    return check_output(['hostname', '-I']).decode().strip()


def csum(packet):
    checksum = 0  # initialize checksum to zero
    words = len(packet) // 2
    for chunk in struct.unpack("!%sH" % words, packet[:words * 2]):
        checksum += chunk  # add up 16-bit words
    if len(packet) % 2 != 0:
        checksum += b'\0'  # add leftover byte
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16  # fold 32-bit into 16-bit
    return ~checksum & 0xffff
