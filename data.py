import sys


class Data:
    """
    This class represents the data contained in a TCP pkt.
    """

    def __init__(self, host: str, path: str):
        """
        Instantiates this Data object to the given host and path.

        :param host: the URL host
        :param path: the URL path
        """

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
        self.chunked = False

    def build_get_message(self) -> str:
        """
        Returns an HTTP GET request.

        :return: the HTTP GET request
        """

        self.request = "GET" + " " + self.path + " " + self.http + self.newline \
                       + "Host:" + " " + self.host + self.newline \
                       + "Connection: Keep-Alive" + self.newline \
                       + self.newline + self.newline
        return self.request

    def get_html(self):
        """
        Retrieves the body/content of the HTTP message in plain text.
        """

        self.content = self.message.split('\r\n\r\n')[1]

    def get_binary(self):
        """
        Retrieves the body/content of the HTTP message in binary.
        """

        self.content = self.message.split(b'\r\n\r\n')[1]

    def get_text_status(self):
        """
        Retrieves the HTTP status code when the message has been decoded.
        """

        status_line_end_index = self.message.find(self.newline)
        status_line = self.message[:status_line_end_index]
        status_line_list = status_line.split(" ")
        self.status = int(status_line_list[1])

    def get_binary_status(self):
        """
        Retrieves the HTTP status code when the message is in binary.
        """

        status_line_end_index = self.message.find(self.newline.encode())
        status_line = self.message[:status_line_end_index]
        status_line_list = status_line.split(b' ')
        self.status = int(status_line_list[1])

    def check_status(self):
        """
        Checks if the message's HTTP status code is 200 (OK) and terminates the program if it isn't.
        """

        if self.status != 200:
            print("Invalid HTTP status code received: " + str(self.status), file=sys.stderr)
            sys.exit(1)

    def get_content_type(self, msg: str or bytes):
        """
        Retrieves the HTTP message's content type.

        :param msg: the HTTP message
        """
        if b'Content-Type: text/x-log' in msg:
            self.message = msg
            self.content_type = "binary"
        else:
            self.message = msg.decode()
            self.content_type = "text"

            if b'Transfer-Encoding: chunked' in msg:
                self.chunked = True

    @staticmethod
    def decode_chunked_encoding(filename):
        with open(filename, "r") as fd:
            contents = fd.read()

        output = ""
        start = 0
        while True:
            new_line_loc = contents.index("\n", start)
            chunk_size = int(contents[start:new_line_loc], base=16)
            start = new_line_loc + 1  # +1 for new line
            output += contents[start:start + chunk_size]
            start = start + chunk_size + 1 # +1 for the new line
            
            if start == len(contents) - 1:
                break

        with open(filename, "w") as fd:
            fd.write(output)

    def save_file(self):
        """
        Saves the HTTP message in a file located in the local directory.
        """

        file_name = self.path.split("/")[-1]
        if file_name in ("/", ""):  # if there's no path
            file_name = "index.html"  # call the file with a default name
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

            if self.chunked:
                self.decode_chunked_encoding(file_name)
