from typing import Tuple
from urllib.parse import urlparse
from tcp_sock import TCPSocket
from http_req import HttpRequest


def get_url_components(url_str: str) -> Tuple[str, str]:
    url = urlparse(url_str)
    return url.netloc, url.path


def download(url: str):
    dst_host, path = get_url_components(url)
    tcp_socket = TCPSocket(dst_host=dst_host)
    if not tcp_socket.connect():
        print("Handshake failed!")
        # TODO: print error and sys.exit

    if path == "/":
        path = ""

    get_req = HttpRequest(target=path)
    get_req.header("Host", dst_host)
    http_req = get_req.build()

    tcp_socket.send(http_pkt=http_req)
    data = tcp_socket.recv()
    print(data.decode())