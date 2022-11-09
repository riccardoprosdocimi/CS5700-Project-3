from random import randint
from utils import csum
import socket
import struct

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
        (
            _,  # don't need version + header length
            _,  # don't need TOS
            _,  # don't need total length
            pkt_id,
            _,  # don't need flags + fragment offset
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
        ) = struct.unpack(HEADER_FORMAT, raw_pkt[:20])

        src_ip = socket.inet_ntoa(src_ip)
        dst_ip = socket.inet_ntoa(dst_ip)
        data = raw_pkt[20:]

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

        zero_csum_raw_pkt = (
                raw_pkt[:10]
                + struct.pack("!H", 0)
                + raw_pkt[12:]
                + data
        )
        check_checksum = csum(zero_csum_raw_pkt)
        print(hex(checksum))
        print(hex(check_checksum))
        if check_checksum == checksum:
            return ip_packet
        else:
            print("IP checksum incorrect")
            return None
