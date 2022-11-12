import sys
from typing import Tuple
from urllib.parse import urlparse
from tcp_sock import TCPSocket
from data import Data


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
    print(http_req)
    tcp_socket.send(http_req)
    data = tcp_socket.recv()
    get_req.get_content_type(data)
    get_req.save_file()
