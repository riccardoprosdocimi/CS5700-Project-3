import sys
from typing import Tuple
from urllib.parse import urlparse
from tcp_sock import TCPSocket
from http_req import HttpRequest
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

    if path == "/":
        path = ""

    get_req = Data(dst_host, path)
    http_req = get_req.build_get_message()
    tcp_socket.send(http_req)
    print(get_req.request)
    data = tcp_socket.recv()
    get_req.get_content_type(data)
    get_req.save_file()



    # get_req = HttpRequest(target=path)
    # get_req.header("Host", dst_host)
    # http_req = get_req.build()
    # print(http_req)
    # tcp_socket.send(http_pkt=http_req)
    # data = tcp_socket.recv()
    # print(data.decode())