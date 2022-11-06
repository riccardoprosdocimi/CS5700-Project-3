class SSocket:
    def __init__(self):
        self.sending_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)