class IPHeader:

    def __init__(self, total_length, source, destination):
        self.version = 4
        self.header_length = 5
        self.service_type = 0
        self.total_length = total_length
        self.identification = 0
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 255
        self.protocol = 6
        self.checksum = 0
        self.source = source
        self.destination = destination
