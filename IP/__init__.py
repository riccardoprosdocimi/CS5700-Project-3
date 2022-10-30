import socket
import struct


class IPHeader:

    def __init__(self, destination, checksum=0):
        self.version = 4
        self.header_length = 5
        self.service_type = 0
        self.total_length = 0
        self.id = 54321
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.checksum = checksum
        self.destination = socket.gethostbyname(destination)
        self.source = socket.gethostbyname(socket.gethostname())
        self.packet = None
        self.create_fields()

    def create_fields(self):
        dscp = 0
        ecn = 0
        self. service_type = (dscp << 2) + ecn

        reserved = 0
        dont_fragment = 0
        more_fragments = 0
        self.flags = (reserved << 7) + (dont_fragment << 6) + (more_fragments << 5) + self.fragment_offset

        return

    def pack_fields(self):
        self.packet = struct.pack(
            '!BBBHHHHBBH4s4s',
            self.version,
            self.header_length,
            self.service_type,
            self.total_length,
            self.id,
            self.flags,
            self.fragment_offset,
            self.ttl,
            self.protocol,
            self.checksum,
            self.source,
            self.destination
        )
        return self.packet

    def csum(self, sent_message, nbytes):
        """
        Generic checksum calculation function.

        :param sent_message:
        :param nbytes:
        :return:
        """

        self.checksum = 0
        while nbytes > 1:
            self.checksum += sent_message
            nbytes -= 2
        if nbytes == 1:
            oddbyte = sent_message
            self.checksum += oddbyte
        self.checksum = (self.checksum >> 16) + (self.checksum & 0xffff)
        self.checksum = self.checksum + (self.checksum >> 16)
        self.checksum = ~self.checksum
        return self.checksum
