from binascii import hexlify
from random import randint
from utils import csum
import socket
import struct

from TCP import TCPPacket

HEADER_SIZE = 20  # IP header size = 20 bytes
HEADER_FORMAT = "!BBHHHBBH4s4s"
MAX_PACKET_SIZE = 65535


class IPPacket:
    def __init__(
        self,
        dst,
        data,
        src,
        mode="send",
        checksum=0,
    ):
        self.version = 4
        self.header_length = 5
        self.service_type = 0
        self.data = data
        self.total_length = len(self.data) + HEADER_SIZE
        self.id = randint(0, MAX_PACKET_SIZE)
        self.flags = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.checksum = checksum
        self.src = src
        if mode == "receive":
            self.dst = dst
        else:
            self.dst = socket.gethostbyname(dst)
        self.packet = None

    def create_fields(self):
        dscp = 0
        ecn = 0
        self.service_type = (dscp << 2) + ecn
        reserved = 0
        dont_fragment = 1
        more_fragments = 0
        self.flags = (reserved << 7) + (dont_fragment << 6) + (more_fragments << 5) + 0

    def pack_fields(self):
        self.create_fields()
        self.packet = struct.pack(
            HEADER_FORMAT,
            self.version << 4 | self.header_length,
            self.service_type,
            self.total_length,
            self.id,
            0,  # Flags + fragment offset
            self.ttl,
            self.protocol,
            self.checksum,
            socket.inet_aton(self.src),
            socket.inet_aton(self.dst),
        )
        self.checksum = csum(self.packet)
        self.packet = (
            self.packet[:10]
            + struct.pack("!H", self.checksum)
            + self.packet[12:]
            + self.data
        )
        return self.packet

    @staticmethod
    def unpack(raw_pkt):
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
            src=src_ip,
            mode="receive",
            checksum=checksum,
        )
        ip_packet.id = pkt_id
        ip_packet.ttl = ttl
        ip_packet.protocol = protocol
        ip_packet.checksum = checksum

        return ip_packet
