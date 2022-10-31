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
        self.fin = 0
        self.syn = 1
        self.rst = 0
        self.psh = 0
        self.ack = 0
        self.urg = 0
        self.window = 5840
        self.checksum = 0
        self.urgent_pointer = 0
        self.packet = None
        self.pseudo_header = None

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
            '!HHIIBBBBBBBHHH',
            self.src_port,  # source port
            self.dst_port,  # destination port
            self.sequence_number,  # sequence number
            self.ack_sequence_number,  # acknowledgment number
            self.data_offset,  # data offset (first 4 bits of the byte, the rest is reserved)
            self.fin,  # finish flag
            self.syn,  # synchronization flag
            self.rst,  # reset flag
            self.psh,  # push flag
            self.ack,  # acknowledgement flag
            self.urg,  # urgent flag
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
