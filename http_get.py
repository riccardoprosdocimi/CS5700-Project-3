from urllib.parse import urlparse
from tcp_sock import TCPSocket


def get_hostname_from_url(url_str: str) -> str:
    url = urlparse(url_str)
    return url.netloc


def download(url: str):
    dst_host = get_hostname_from_url(url)
    tcp_socket = TCPSocket(dst_host=dst_host)
    if not tcp_socket.connect():
        print("Handshake failed!")
