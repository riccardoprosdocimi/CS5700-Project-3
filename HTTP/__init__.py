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
        self.status = 0

    def bild_get_message(self, page_url):
        self.request = "GET" + " " + page_url + " " + self.http + self.newline \
              + "Host:" + " " + self.host \
              + self.newline + self.newline
        return self.request

    def get_html(self, msg):
        self.content = msg.split('\n\n\n\n')[1]
        return self.content

    def get_status(self, msg):
        status_line_end_index = msg.find(self.newline)
        status_line = msg[:status_line_end_index]
        status_line_list = status_line.split(" ")
        self.status = int(status_line_list[1])
        return self.status

    def save_file(self):
        if self.status != 200:
            print("Invalid HTTP status code received: " + str(self.status), file=sys.stderr)
            sys.exit(1)
        else:
            file_name = self.host.split("/")[-1]
            open(file_name, "wb").write(self.content)
