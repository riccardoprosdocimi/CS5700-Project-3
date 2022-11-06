import sys
import time
from binascii import hexlify
from functools import reduce
from random import randint
from utils import csum
from IP import IPPacket
import socket
import struct

TIMEOUT = 60  # if packet not ACKed within 1 minute -> packet lost -> retransmit


class TCPPacket:
    def __init__(self, src_host,
                 src_port,
                 dst_host,
                 dst_port,
                 ip_packet: IPPacket = ""):
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.sending_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.sequence_number = 0
        self.ack_sequence_number = 0
        self.data_offset = 5 << 4  # 4 reserved bits out of the byte
        self.flags = 0b00000000  # 2 reserved bits, finish, synchronization, reset, push, acknowledgement, urgent flags
        self.fin = False  # finish flag
        self.syn = False  # synchronization flag
        self.rst = False  # reset flag
        self.psh = False  # push flag
        self.ack = False  # acknowledgement flag
        self.urg = False  # urgent flag
        self.window = 65535  # max window size
        self.checksum = 0
        self.urgent_pointer = 0
        self.data = ip_packet
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
            self.sequence_number,  # sequence number
            self.ack_sequence_number,  # acknowledgment number
            self.data_offset,  # data offset (first 4 bits of the byte, the rest is reserved)
            self.flags,  # flags
            self.window,  # window
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

    def recv(self):
        incoming_packets = dict()
        while True:
            self.packet = self._recv()
            if not self.packet:
                print("The server is down", file=sys.stderr)
                self.start_close_connection()
                sys.exit(1)
            elif self.ack and self.sequence_number not in incoming_packets:
                incoming_packets[self.sequence_number] = self.data
                self.ack_sequence_number = self.sequence_number + len(self.data.total_length)
                if self.fin:  # server wants to close connection
                    self.end_close_connection()
                    break  # shut down connection
                else:
                    self._send()
        incoming_ordered_packets = sorted(incoming_packets.items())
        self.data = reduce(lambda packet_x, packet_y: packet_x + packet_y[-1], incoming_ordered_packets, "")

    def _recv(self):
        self.receiving_socket.settimeout(TIMEOUT)
        try:
            while True:
                raw_data = self.receiving_socket.recv(self.window)
                ip_packet = self.data.unpack_packet(raw_data)
                # if server's IP source and destination addresses don't match client's and checksum doesn't add up
                if ip_packet.dst != self.src_host or \
                        ip_packet.src != self.dst_host or \
                        ip_packet.checksum != 0:
                    continue  # ignore the packet
                tcp_packet = self.unpack_packet(ip_packet.data, raw_data)
                # if server's TCP source and destination ports don't match client's and checksum doesn't add up
                if tcp_packet.src_port != self.dst_port or\
                        tcp_packet.dst_port != self.src_port or\
                        tcp_packet.checksum != 0:
                    continue  # ignore the packet
                return tcp_packet
        except socket.timeout:
            return None

    def recv_ack(self, sequence_increment: int = 0):
        start_time = time.time()
        while time.time() - start_time < TIMEOUT:
            self.packet = self._recv()
            if not self.packet:  # if packet is empty
                break  # abort
            if self.packet.ack and \
                    self.packet.ack_sequence_number >= self.sequence_number + len(self.data.data) + sequence_increment:
                self.sequence_number = self.packet.ack_sequence_number
                self.ack_sequence_number = self.packet.sequence_number + sequence_increment
                return True
        return False

    def _send(self, data=None):
        self.ack = True
        self.syn = True
        self.data.data = data
        self.pack_fields()
        self.data.pack_fields()
        self.sending_socket.sendto(self.data, (self.dst_host, self.dst_port))

    def send(self, data):
        self._send(data)
        while not self.recv_ack():
            self._send(data)
        self.data.data = None

    def connect(self):
        self.sequence_number = randint(0, (2 << 31) - 1)  # max number of possible sequence numbers = 2^32


    @staticmethod
    def unpack_packet(ip_pkt, raw_tcp_pkt):
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
