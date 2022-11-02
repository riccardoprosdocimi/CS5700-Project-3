from binascii import hexlify
from utils import csum
import socket
import struct


class IPPacket:
    def __init__(
        self,
        dst,
        data,
        mode="send",
        src=socket.gethostbyname(socket.gethostname()),
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
        self.src = src
        if mode == "receive":
            self.dst = dst
        else:
            self.dst = socket.gethostbyname(dst)
        self.data = data
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
            self.src,
            self.dst,
        )
        self.checksum = csum
        return self.packet

    @staticmethod
    def from_bytes(raw_pkt):
        raw_ip_header = raw_pkt[14:35]
        total_length_raw = raw_ip_header[2:4]
        (total_length,) = struct.unpack("!H", total_length_raw)
        data = raw_pkt[35:]
        pkt_id_raw = raw_ip_header[4:6]
        (pkt_id,) = struct.unpack("!H", pkt_id_raw)

        ttl_raw = raw_ip_header[8:9]
        (ttl,) = struct.unpack("!c", ttl_raw)
        ttl = int(hexlify(ttl), base=16)

        protocol_raw = raw_ip_header[9:10]
        (protocol,) = struct.unpack("!c", protocol_raw)
        protocol = int(hexlify(protocol), base=16)

        checksum_raw = raw_ip_header[10:12]
        (checksum,) = struct.unpack("!H", checksum_raw)

        src_ip_raw = raw_ip_header[12:16]
        src_ip = socket.inet_ntoa(src_ip_raw)

        dst_ip_raw = raw_ip_header[16:20]
        dst_ip = socket.inet_ntoa(dst_ip_raw)

        ip_packet = IPPacket(
            dst=dst_ip,
            data=data,
            mode="receive",
            src=src_ip,
            checksum=checksum,
        )
        ip_packet.id = pkt_id
        ip_packet.ttl = ttl
        ip_packet.protocol = protocol
        ip_packet.checksum = checksum

        return ip_packet
