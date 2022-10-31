import array
import socket
import struct


class TCPPacket:

    def __init__(self, src_host, src_port, dst_host, dst_port):
        self.src_host = src_host
        self.src_port = src_port
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.sequence_number = 0
        self.ack_sequence_number = 0
        self.data_offset = 5 << 4
        self.flags = 0b000000000  # finish flag, synchronization flag, reset flag, acknowledgement flag, urgent flag
        self.fin = 0b000000000  # finish flag
        self.syn = 0b000000000  # synchronization flag
        self.rst = 0b000000000  # reset flag
        self.psh = 0b000000000  # push flag
        self.ack = 0b000000000  # acknowledgement flag
        self.urg = 0b000000000  # urgent flag
        self.window = 5840
        self.checksum = 0
        self.urgent_pointer = 0
        self.packet = None
        self.pseudo_header = None

    def create_flags(self):
        if self.fin is True:
            self.flags = self.flags | 0b000000000
        if self.syn is True:
            self.flags = self.flags | 0b000000000
        if self.rst is True:
            self.flags = self.flags | 0b000000000
        if self.psh is True:
            self.flags = self.flags | 0b000000000
        if self.ack is True:
            self.flags = self.flags | 0b000000000
        if self.urg is True:
            self.flags = self.flags | 0b000000000

    @staticmethod
    def csum(packet):
        if len(packet) % 2 != 0:
            packet += b'\0'
        checksum = sum(array.array("H", packet))  # create array of fixed element types to calculate sum of 16-bit words
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return (~checksum) & 0xffff

    def pack_fields(self):
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
            self.urgent_pointer  # urgent pointer
        )
        self.pseudo_header = struct.pack(
            '!4s4sHH',
            socket.inet_aton(self.src_host),  # source address
            socket.inet_aton(self.dst_host),  # destination address
            socket.IPPROTO_TCP,  # protocol ID
            len(self.packet)  # packet length
        )
        self.checksum = self.csum(self.pseudo_header + self.packet)
        self.packet = self.packet[:16] + struct.pack('H', self.checksum) + self.packet[18:]
        return self.packet
