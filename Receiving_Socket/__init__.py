import socket


class RSocket:
    def __init__(self):
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)