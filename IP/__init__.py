from binascii import hexlify
import socket
import struct


class IPPacket:
    def __init__(
        self,
        destination,
        data,
        mode="send",
        source=socket.gethostbyname(socket.gethostname()),
        checksum=0,
    ):
        self.version = 4
        self.header_length = 5
        self.service_type = 0
        self.total_length = len(data) + 20
        self.id = 0
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.checksum = checksum
        if mode == "receive":
            self.destination = destination
        else:
            self.destination = socket.gethostbyname(destination)
        self.source = source
        self.packet = None
        self.create_fields()

    def create_fields(self):
        dscp = 0
        ecn = 0
        self.service_type = (dscp << 2) + ecn

        reserved = 0
        dont_fragment = 0
        more_fragments = 0
        self.flags = (
            (reserved << 7)
            + (dont_fragment << 6)
            + (more_fragments << 5)
            + self.fragment_offset
        )

        return

    def pack_fields(self):
        self.packet = struct.pack(
            "!BBBHHHHBBH4s4s",
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
            self.destination,
        )
        return self.packet

    def csum(self, sent_message, nbytes):
        """
        Generic checksum calculation function.

        :param sent_message:
        :param nbytes:
        :return:
        """

        while nbytes > 1:
            self.checksum += sent_message
            nbytes -= 2
        if nbytes == 1:
            oddbyte = sent_message
            self.checksum += oddbyte
        self.checksum = (self.checksum >> 16) + (self.checksum & 0xFFFF)
        self.checksum = self.checksum + (self.checksum >> 16)
        self.checksum = ~self.checksum
        return self.checksum

    @staticmethod
    def from_bytes(raw_pkt):
        raw_ip_header = raw_pkt[14:35]
        total_length_raw = raw_ip_header[2:4]
        (total_length,) = struct.unpack("!h", total_length_raw)
        data = raw_pkt[35 : 35 + total_length - 20]  # header length = 20

        pkt_id_raw = raw_ip_header[4:6]
        (pkt_id,) = struct.unpack("!h", pkt_id_raw)

        ttl_raw = raw_ip_header[8:9]
        (ttl,) = struct.unpack("!c", ttl_raw)
        ttl = int(hexlify(ttl), base=16)

        protocol_raw = raw_ip_header[9:10]
        (protocol,) = struct.unpack("!c", protocol_raw)
        protocol = int(hexlify(protocol), base=16)

        checksum_raw = raw_ip_header[10:12]
        (checksum,) = struct.unpack("!h", checksum_raw)

        src_ip_raw = raw_ip_header[12:16]
        src_ip = socket.inet_ntoa(src_ip_raw)

        dst_ip_raw = raw_ip_header[16:20]
        dst_ip = socket.inet_ntoa(dst_ip_raw)

        ip_packet = IPPacket(src_ip, dst_ip, data)
        ip_packet.id = pkt_id
        ip_packet.ttl = ttl
        ip_packet.protocol = protocol
        ip_packet.checksum = checksum

        return ip_packet


PROTOCOLS_TO_CAPTURE = (socket.IPPROTO_TCP,)
