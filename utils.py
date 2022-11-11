import socket
import struct


def get_nw_interface_name() -> str:
    prefixes = ("enp", "eth", "wlp")
    for _, int_name in socket.if_nameindex():
        for prefix in prefixes:
            if int_name.startswith(prefix):
                return int_name
    raise ValueError("Cannot find a valid network interface")


def get_local_ip_addr():
    """
    Returns the source's IP address.

    :return: the source's IP address
    """

    from subprocess import check_output
    return check_output(['hostname', '-I']).decode().strip()


def calculate_checksum(pkt):
    """
    Calculates the checksum of a packet.

    :param pkt: the packet
    :return: the checksum
    """

    checksum = 0  # initialize checksum to zero
    words = len(pkt) // 2  # calculate number of 16-bit chunks
    for chunk in struct.unpack("!%sH" % words, pkt[:words * 2]):
        checksum += chunk  # add up 16-bit chunks
    if len(pkt) % 2 != 0:  # if pkt length is odd
        checksum += 0  # add leftover byte
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    return ~checksum & 0xffff
