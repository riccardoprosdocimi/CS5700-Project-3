from binascii import hexlify
from utils import csum
import socket
import struct


class TCPPacket:
    def __init__(self, src_host, src_port, dst_host, dst_port):
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
        self.urgent_pointer = 0
        self.packet = None
        self.pseudo_header = None

    def create_flags(self):
        if self.fin is True:
            self.flags = self.flags | 0b1
        if self.syn is True:
            self.flags = self.flags | 0b1 << 1
        if self.rst is True:
            self.flags = self.flags | 0b1 << 2
        if self.psh is True:
            self.flags = self.flags | 0b1 << 3
        if self.ack is True:
            self.flags = self.flags | 0b1 << 4
        if self.urg is True:
            self.flags = self.flags | 0b1 << 5

    def pack_fields(self):
        self.create_flags()
        self.packet = struct.pack(
            '!HHIIBBHHH',
            self.src_port,  # source port
            self.dst_port,  # destination port
            self.seq_num,  # sequence number
            self.ack_num,  # acknowledgment number
            self.data_offset,  # data offset (first 4 bits of the byte, the rest is reserved)
            self.flags,  # flags
            self.adv_wnd,  # window
            self.checksum,  # checksum
            self.urgent_pointer,  # urgent pointer
        )
        self.pseudo_header = struct.pack(
            "!4s4sHH",
            socket.inet_aton(self.src_host),  # source address
            socket.inet_aton(self.dst_host),  # destination address
            socket.IPPROTO_TCP,  # protocol ID
            len(self.packet),  # packet length
        )
        self.checksum = csum(self.pseudo_header + self.packet)
        self.packet = (
            self.packet[:16] + struct.pack("H", self.checksum) + self.packet[18:]
        )
        return self.packet

    @staticmethod
    def from_bytes(ip_pkt, raw_tcp_pkt):
        src_port_raw = raw_tcp_pkt[0:2]
        (src_port,) = struct.unpack("!H", src_port_raw)

        dst_port_raw = raw_tcp_pkt[2:4]
        (dst_port,) = struct.unpack("!H", dst_port_raw)

        seq_num_raw = raw_tcp_pkt[4:8]
        (seq_num,) = struct.unpack("!I", seq_num_raw)

        ack_num_raw = raw_tcp_pkt[8:12]
        (ack_num,) = struct.unpack("!I", ack_num_raw)

        flag_block_raw = raw_tcp_pkt[12:14]
        (flag_block,) = struct.unpack("!2s", flag_block_raw)
        flag_bits = bin(int(hexlify(flag_block), base=16))

        fin = flag_bits[-1] == "1"
        syn = flag_bits[-2] == "1"
        rst = flag_bits[-3] == "1"
        psh = flag_bits[-4] == "1"
        ack = flag_bits[-5] == "1"
        urg = flag_bits[-6] == "1"

        adv_wnd_raw = raw_tcp_pkt[14:16]
        (adv_wnd,) = struct.unpack("!H", adv_wnd_raw)

        checksum_raw = raw_tcp_pkt[16:18]
        (checksum,) = struct.unpack("!H", checksum_raw)

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

        tcp_pkt.fin = fin
        tcp_pkt.syn = syn
        tcp_pkt.rst = rst
        tcp_pkt.psh = psh
        tcp_pkt.ack = ack
        tcp_pkt.urg = urg

        return tcp_pkt
