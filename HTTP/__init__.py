import sys


class Data:

    def __init__(self, host):
        self.port = 80
        self.buffer = 65535  # buffer size related to TCP window size
        self.host = host
        self.http = "HTTP/1.1"
        self.newline = '\r\n'
        self.request = ""
        self.content = None
        self.message = None
        self.status = 0
        self.content_type = ""

    def build_get_message(self):
        self.request = "GET" + " " + self.host + " " + self.http + self.newline \
              + "Host:" + " " + self.host \
              + self.newline + self.newline
        return self.request

    def get_html(self):
        self.content = self.message.split('\n\n\n\n')[1]
        return self.content

    def get_status(self):
        status_line_end_index = self.message.find(self.newline)
        status_line = self.message[:status_line_end_index]
        status_line_list = status_line.split(" ")
        self.status = int(status_line_list[1])
        return self.status

    def get_content_type(self):
        if "Content-Type: text/x-log" in self.message:
            self.content_type = "binary"
        else:
            self.content_type = "text"

    def save_file(self):
        if self.status != 200:
            print("Invalid HTTP status code received: " + str(self.status), file=sys.stderr)
            sys.exit(1)
        else:
            file_name = self.host.split("/")[-1]
            if self.content_type == "binary":
                open(file_name, "wb").write(self.content)
            else:
                open(file_name, "w").write(self.content)
