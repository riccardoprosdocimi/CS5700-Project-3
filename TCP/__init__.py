import sys
import time
from binascii import hexlify
from functools import reduce
from random import randint
from utils import csum
from HTTP import Data
import socket
import struct

TIMEOUT = 60  # if packet not ACKed within 1 minute -> packet lost -> retransmit
HEADER_FORMAT = "!HHIIBBHHH"
PSEUDO_HEADER_FORMAT = "!4s4sBBH"
WINDOW_SIZE = 65535


class TCPPacket:
    def __init__(self, src_host, src_port, dst_host, dst_port, http_packet=""):
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
        self.http_packet = http_packet.encode()

    def create_flags(self):
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

    def pack_fields(self):
        self.create_flags()
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
            self.urgent_pointer,  # urgent pointer
        )
        reserved = 0
        self.pseudo_header = struct.pack(
            PSEUDO_HEADER_FORMAT,
            socket.inet_aton(self.src_host),  # source address
            socket.inet_aton(self.dst_host),  # destination address
            reserved,
            socket.IPPROTO_TCP,  # protocol ID
            len(self.packet) + len(self.http_packet),  # packet length
        )
        self.checksum = csum(self.pseudo_header + self.packet + self.http_packet)
        self.packet = (
            self.packet[:16]
            + struct.pack("!H", self.checksum)
            + self.packet[18:]
            + self.http_packet
        )
        return self.packet

    def recv(self):
        incoming_packets = dict()
        while True:
            self.header = self._recv()
            if not self.header:
                print("The server is down", file=sys.stderr)
                self.start_close_connection()
                sys.exit(1)
            elif self.ack and self.sequence_number not in incoming_packets:
                incoming_packets[self.sequence_number] = self.data
                self.ack_sequence_number = self.sequence_number + len(
                    self.data.total_length
                )
                if self.fin:  # server wants to close connection
                    self.end_close_connection()
                    break  # shut down connection
                else:
                    self._send()
        incoming_ordered_packets = sorted(incoming_packets.items())
        self.data = reduce(
            lambda packet_x, packet_y: packet_x + packet_y[-1],
            incoming_ordered_packets,
            "",
        )

    def _recv(self):
        self.receiving_socket.settimeout(TIMEOUT)
        try:
            while True:
                raw_data = self.receiving_socket.recv(self.window)
                ip_packet = self.data.unpack_packet(raw_data)
                # if server's IP source and destination addresses don't match client's and checksum doesn't add up
                if (
                    ip_packet.dst != self.src_host
                    or ip_packet.src != self.dst_host
                    or ip_packet.checksum != 0
                ):
                    continue  # ignore the packet
                tcp_packet = self.unpack_packet(ip_packet.data, raw_data)
                # if server's TCP source and destination ports don't match client's and checksum doesn't add up
                if (
                    tcp_packet.src_port != self.dst_port
                    or tcp_packet.dst_port != self.src_port
                    or tcp_packet.checksum != 0
                ):
                    continue  # ignore the packet
                return tcp_packet
        except socket.timeout:
            return None

    def recv_ack(self, sequence_increment: int = 0):
        start_time = time.time()
        while time.time() - start_time < TIMEOUT:
            self.header = self._recv()
            if not self.header:  # if packet is empty
                break  # abort
            if (
                self.header.ack
                and self.header.ack_sequence_number
                >= self.sequence_number + self.data.total_length + sequence_increment
            ):
                self.sequence_number = self.header.ack_sequence_number
                self.ack_sequence_number = (
                    self.header.sequence_number + sequence_increment
                )
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
        self.sequence_number = randint(
            0, (2 << 31) - 1
        )  # max number of possible sequence numbers = 2^32

    @staticmethod
    def unpack(ip_pkt, raw_tcp_pkt):
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
        ) = struct.unpack("!HHIIBBHHH", raw_tcp_pkt[:20])

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

        tcp_pkt.fin = fin
        tcp_pkt.syn = syn
        tcp_pkt.rst = rst
        tcp_pkt.psh = psh
        tcp_pkt.ack = ack
        tcp_pkt.urg = urg

        return tcp_pkt
