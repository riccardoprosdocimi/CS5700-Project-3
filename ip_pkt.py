import socket
import struct
from random import randint
from utils import calculate_checksum


HEADER_SIZE = 20  # IP header size -> 20 bytes
HEADER_FORMAT = "!BBHHHBBH4s4s"
MAX_PACKET_SIZE = 65535  # maximum byte-size of a TCP pkt


class IPPacket:
    """
    This class represents the IP pkt.
    """

    def __init__(
        self,
        dst,
        data,
        src,
        mode="send",
        checksum=0,
    ):
        """
        Instantiates this IPPacket object to the given destination address, data, source address, mode, and
        checksum.

        :param dst: the destination address
        :param data: the data
        :param src: the source address
        :param mode: the mode (send or receive)
        :param checksum: the checksum
        """

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

    def shift_fields(self):
        """
        Performs bit shifting for bit-sized header fields.
        """

        dscp = 0  # differentiated services code point
        ecn = 0  # explicit congestion notification
        self.service_type = (dscp << 2) + ecn
        reserved = 0
        dont_fragment = 1
        more_fragments = 0
        self.flags = (reserved << 7) + (dont_fragment << 6) + (more_fragments << 5) + 0

    def pack(self) -> bytes:
        """
        Formats and encodes the header fields.

        :return: the encoded IP pkt
        """

        self.shift_fields()
        self.packet = struct.pack(
            HEADER_FORMAT,
            self.version << 4 | self.header_length,
            self.service_type,
            self.total_length,
            self.id,
            0,  # flags + fragment offset
            self.ttl,
            self.protocol,
            self.checksum,  # initialized to 0
            socket.inet_aton(self.src),
            socket.inet_aton(self.dst),
        )
        self.checksum = calculate_checksum(self.packet)  # calculate checksum
        self.packet = (  # inject calculated checksum in the right spot
            self.packet[:10]
            + struct.pack("!H", self.checksum)
            + self.packet[12:]
            + self.data
        )
        return self.packet

    @staticmethod
    def unpack(raw_pkt: bytes) -> str or None:
        """
        Decodes and parses incoming IP packets.

        :param raw_pkt: the encoded IP pkt
        :return: the decoded IP pkt or None
        """

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
        ip_pkt = IPPacket(
            dst=dst_ip,
            data=data,
            src=src_ip,
            mode="receive",
            checksum=checksum,
        )
        ip_pkt.id = pkt_id
        ip_pkt.ttl = ttl
        ip_pkt.protocol = protocol
        ip_pkt.checksum = checksum
        zero_csum_raw_ip_pkt = (  # reset the incoming packet's checksum to 0
                raw_pkt[:10]
                + struct.pack("!H", 0)
                + raw_pkt[12:20]
        )
        check_checksum = calculate_checksum(zero_csum_raw_ip_pkt)  # calculate checksum
        if check_checksum == checksum:  # compare locally calculated checksum with server's one
            return ip_pkt
        else:
            return None
