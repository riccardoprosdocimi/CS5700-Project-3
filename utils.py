import socket
import struct
import sys
from typing import Tuple
from urllib.parse import urlparse
from tcp_sock import TCPSocket
from data import Data


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


def get_url_components(url: str) -> Tuple[str, str]:
    """
    Returns the URL host and path.

    :param url: the full URL
    :return: the URL host and path
    """

    url = urlparse(url)
    return url.netloc, url.path


def download(url: str):
    """
    Downloads the HTTP message.

    :param url: the full URL
    """

    dst_host, path = get_url_components(url)
    tcp_socket = TCPSocket(dst_host=dst_host)
    if not tcp_socket.connect():  # connection failed
        print("Handshake failed", file=sys.stderr)
        sys.exit(1)
    if path == "":  # if there's no path
        path = "/"  # add a trailing forward slash
    get_req = Data(dst_host, path)
    http_req = get_req.build_get_message()
    tcp_socket.send(http_req)
    data = tcp_socket.recv()
    get_req.get_content_type(data)
    get_req.save_file()
