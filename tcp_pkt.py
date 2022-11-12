import socket
import struct
from ip_pkt import IPPacket, calculate_checksum

HEADER_FORMAT = "!HHIIBBHHH"
PSEUDO_HEADER_FORMAT = "!4s4sBBH"


class TCPPacket:
    """
    This class represents a TCP pkt.
    """

    def __init__(self, src_host: str, src_port: int, dst_host: str, dst_port: int, payload: str = ""):
        """
        Instantiates a TCPPacket object to the given source address, source port, destination address, destination
        port, and payload.

        :param src_host: the source address
        :param src_port: the source port
        :param dst_host: the destination address
        :param dst_port: the destination port
        :param payload: the payload
        """

        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 5 << 4  # 4 reserved bits out of the byte
        self.flags = 0b00000000  # 2 reserved bits, finish, synchronization, reset, push, acknowledgement, urgent flags
        self.fin = False  # finish flag
        self.syn = False  # synchronization flag
        self.rst = False  # reset flag
        self.psh = False  # push flag
        self.ack = False  # acknowledgement flag
        self.urg = False  # urgent flag
        self.adv_wnd = 65535  # max window size
        self.checksum = 0
        self.urg_ptr = 0
        self.packet = None
        self.pseudo_header = None
        self.payload = payload.encode()

    def set_flags(self):
        """
        Sets the flags of this TCP pkt.
        """

        if self.fin:
            self.flags |= 1
        if self.syn:
            self.flags |= 1 << 1
        if self.rst:
            self.flags |= 1 << 2
        if self.psh:
            self.flags |= 1 << 3
        if self.ack:
            self.flags |= 1 << 4
        if self.urg:
            self.flags |= 1 << 5

    def pack(self) -> bytes:
        """
        Formats and encodes the header fields.
        """

        self.set_flags()
        self.packet = struct.pack(
            HEADER_FORMAT,
            self.src_port,  # source port
            self.dst_port,  # destination port
            self.seq_num,  # sequence number
            self.ack_num,  # acknowledgment number
            self.data_offset,  # data offset (first 4 bits of the byte, the rest is reserved)
            self.flags,  # flags
            self.adv_wnd,  # window
            self.checksum,  # checksum
            self.urg_ptr,  # urgent pointer
        )
        self.pseudo_header = struct.pack(  # packs an IP pseudo header for calculating the checksum
            PSEUDO_HEADER_FORMAT,
            socket.inet_aton(self.src_host),  # source address
            socket.inet_aton(self.dst_host),  # destination address
            0,  # reserved
            socket.IPPROTO_TCP,  # protocol ID
            len(self.packet) + len(self.payload),  # pkt length
        )
        self.checksum = calculate_checksum(self.pseudo_header + self.packet + self.payload)  # calculate checksum
        self.packet = (  # inject calculated checksum in the right spot
            self.packet[:16]
            + struct.pack("!H", self.checksum)
            + self.packet[18:]
            + self.payload
        )
        return self.packet

    @staticmethod
    def unpack(ip_pkt: IPPacket, raw_tcp_pkt: bytes) -> str or None:
        """
        Decodes and parses incoming TCP packets.

        :param ip_pkt: the IP pkt
        :param raw_tcp_pkt: the encoded TCP pkt
        :return: the decoded TCP pkt or None
        """

        (
            src_port,
            dst_port,
            seq_num,
            ack_num,
            _,  # don't need header length
            flag_byte,
            adv_wnd,
            checksum,
            urg,
        ) = struct.unpack(HEADER_FORMAT, raw_tcp_pkt[:20])
        fin = flag_byte & 1 == 1
        syn = flag_byte & 1 << 1 == 1 << 1
        rst = flag_byte & 1 << 2 == 1 << 2
        psh = flag_byte & 1 << 3 == 1 << 3
        ack = flag_byte & 1 << 4 == 1 << 4
        urg = flag_byte & 1 << 5 == 1 << 5
        tcp_pkt = TCPPacket(
            src_host=ip_pkt.src,
            src_port=src_port,
            dst_host=ip_pkt.dst,
            dst_port=dst_port,
        )
        tcp_pkt.seq_num = seq_num
        tcp_pkt.ack_num = ack_num
        tcp_pkt.adv_wnd = adv_wnd
        tcp_pkt.checksum = checksum
        tcp_pkt.payload = raw_tcp_pkt[20:]
        tcp_pkt.fin = fin
        tcp_pkt.syn = syn
        tcp_pkt.rst = rst
        tcp_pkt.psh = psh
        tcp_pkt.ack = ack
        tcp_pkt.urg = urg
        pseudo_header = struct.pack(
            PSEUDO_HEADER_FORMAT,
            socket.inet_aton(ip_pkt.src),
            socket.inet_aton(ip_pkt.dst),
            0,  # reserved
            socket.IPPROTO_TCP,
            len(raw_tcp_pkt),  # payload included
        )
        zero_csum_raw_tcp_pkt = (  # reset the incoming packet's checksum to 0
                raw_tcp_pkt[:16]
                + struct.pack("!H", 0)
                + raw_tcp_pkt[18:]
        )
        check_checksum = calculate_checksum(pseudo_header + zero_csum_raw_tcp_pkt)  # calculate checksum

        if check_checksum == checksum:  # compare locally calculated checksum with server's one
            return tcp_pkt
        else:
            try:
                print(tcp_pkt.payload.decode())
                print(hex(check_checksum), hex(checksum), tcp_pkt.psh, tcp_pkt.ack)
            except UnicodeDecodeError:
                pass
            return None
