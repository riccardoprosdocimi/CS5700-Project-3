import sys


class Data:

    def __init__(self, host, path):
        self.path = path
        self.host = host
        self.http = "HTTP/1.1"
        self.newline = '\r\n'
        self.request = ""
        self.message = None
        self.content = None
        self.content_length = str(0)
        self.status = 0
        self.content_type = ""

    def build_get_message(self):
        self.request = "GET" + " " + self.path + " " + self.http + self.newline \
                       + "Host:" + " " + self.host + self.newline \
                       + "Connection: Keep-Alive" + self.newline \
                       + self.newline + self.newline
        return self.request

    def get_html(self):
        self.content = self.message.split('\r\n\r\n')[1]

    def get_binary(self):
        self.content = self.message.split(b'\r\n\r\n')[1]

    def get_text_status(self):
        status_line_end_index = self.message.find(self.newline)
        status_line = self.message[:status_line_end_index]
        status_line_list = status_line.split(" ")
        self.status = int(status_line_list[1])

    def get_binary_status(self):
        status_line_end_index = self.message.find(b'self.newline')
        status_line = self.message[:status_line_end_index]
        status_line_list = status_line.split(b' ')
        self.status = int(status_line_list[1])

    def check_status(self):
        if self.status != 200:
            print("Invalid HTTP status code received: " + str(self.status), file=sys.stderr)
            sys.exit(1)

    def get_content_type(self, msg: str or bytes):
        if b'Content-Type: text/x-log' in msg:
            self.message = msg
            self.content_type = "binary"
        else:
            self.message = msg.decode()
            self.content_type = "text"

    def save_file(self):
        if "/" not in self.path:
            file_name = "index.html"
        else:
            file_name = self.path.split("/")[-1]
        if self.content_type == "binary":
            self.get_binary_status()
            self.check_status()
            self.get_binary()
            open(file_name, "wb").write(self.content)
        else:
            self.get_text_status()
            self.check_status()
            self.get_html()
            open(file_name, "w").write(self.content)
