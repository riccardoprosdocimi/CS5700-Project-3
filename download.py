import sys
from typing import Tuple
from urllib.parse import urlparse
from tcp_sock import TCPSocket
from data import Data


def get_url_components(url_str: str) -> Tuple[str, str]:
    url = urlparse(url_str)
    return url.netloc, url.path


def download(url: str):
    dst_host, path = get_url_components(url)
    tcp_socket = TCPSocket(dst_host=dst_host)
    if not tcp_socket.connect():
        print("Handshake failed", file=sys.stderr)
        sys.exit(1)

    if path == "":
        path = "/"

    get_req = Data(dst_host, path)
    http_req = get_req.build_get_message()
    tcp_socket.send(http_req)
    data = tcp_socket.recv()
    get_req.get_content_type(data)
    get_req.save_file()
