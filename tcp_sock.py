import socket
import sys
from random import randint
from utils import get_local_ip_addr
from tcp_pkt import TCPPacket
from ip_pkt import IPPacket

TEST = "0.0.0.0"
MAX_CWND = 1000
MAX_PACKET_SIZE = 65535  # maximum byte-size of a TCP pkt
MSS = 1460


class TCPSocket:
    """
    This class represents the TCP socket.
    """

    def __init__(self, dst_host: str):
        """
        Instantiates this TCPSocket object to the given destination address.

        :param dst_host: the destination address
        """

        self.adv_wnd = MAX_PACKET_SIZE
        self.rto = 60  # seconds
        self.recv_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )
        self.recv_sock.settimeout(self.rto)
        self.send_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        self.dst_host = socket.gethostbyname(dst_host)
        self.dst_port = 80  # HTTP
        self.src_host = get_local_ip_addr()
        self.src_port = randint(1025, MAX_PACKET_SIZE)
        self.try_port()
        self.seq_num = randint(0, 2**32 - 1)
        self.start_seq_num = self.seq_num
        self.ack_num = 0
        self.last_pkt = None  # cache last pkt for retransmission
        self.counter = 3  # retransmit 3 times, then end connection
        # congestion control
        self.cwnd = 1
        self.dst_adv_wnd = 1
        self.buf = bytearray()

    def try_port(self):
        """
        Checks if a port is available locally.
        """

        test_sock = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )  # new socket object for testing the port
        while True:
            try:
                test_sock.bind((TEST, self.src_port))
                break  # the port is open
            except:  # the port is busy
                self.src_port = randint(1025, MAX_PACKET_SIZE)
        test_sock.close()

    def connect(self) -> bool:
        """
        Performs the three-way handshake to establish a TCP connection.

        :return: True if the connection is successful, False otherwise
        """

        # 3-way handshake
        syn_pkt = self.create_tcp_pkt()
        syn_pkt.syn = True
        self.send_pkt(syn_pkt)
        recvd_pkt = self.recv_pkt()
        self.ack_num = recvd_pkt.seq_num + 1
        if recvd_pkt and recvd_pkt.syn and recvd_pkt.ack:
            self.send_ack()
            return True
        else:
            self.close()
            return False

    def close(self):
        """
        Shuts down the connection.
        """

        fin_ack_pkt = self.create_tcp_pkt()
        fin_ack_pkt.fin = True
        fin_ack_pkt.ack = True
        self.send_pkt(fin_ack_pkt)
        recvd_pkt = self.recv_pkt()
        self.ack_num = recvd_pkt.seq_num + 1
        self.recv_sock.close()
        self.send_sock.close()

    def send(self, pkt: str):
        """
        Sends a pkt.

        :param pkt: the pkt
        """
        self.buf += pkt.encode()

        # Determine the actual size of the congestion window in bytes
        wnd_start_offset = self.seq_num - self.start_seq_num - 1
        wnd_size_bytes = MSS * min(self.dst_adv_wnd, self.cwnd)

        # Sliding window
        for offset in range(wnd_start_offset, len(self.buf), wnd_size_bytes):
            payload = self.buf[offset : offset + wnd_size_bytes]

            tcp_pkt = self.create_tcp_pkt()
            tcp_pkt.payload = payload
            tcp_pkt.psh = True
            tcp_pkt.ack = True
            
            self.send_pkt(tcp_pkt=tcp_pkt)
            recvd_pkt = self.recv_pkt()
            if recvd_pkt.ack:
                self.ack_num = recvd_pkt.seq_num

    def recv(self) -> bytearray:
        """
        Receives, processes, and returns encoded packets.

        :return: the encoded pkt
        """

        window = {}  # buffer
        while True:
            recvd_pkt = self.recv_pkt()
            if recvd_pkt.ack and recvd_pkt.seq_num not in window:  # if it's an ACK pkt
                self.ack_num = recvd_pkt.seq_num + len(recvd_pkt.payload)

                if recvd_pkt.payload:  # check for duplicate packets & None payloads
                    window[
                        recvd_pkt.seq_num
                    ] = recvd_pkt.payload  # add to buffer -> key=seq_num value=payload
                    self.send_ack()  # send an ACK

                if (
                    recvd_pkt.fin or recvd_pkt.rst
                ):  # server wants to close the connection
                    self.close()  # close connection
                    break  # stop receiving

        sorted_seq_nums = sorted(
            window.keys()
        )  # sort out of order packets by the seq_num
        data = bytearray()
        for (
            seq_num
        ) in sorted_seq_nums:  # reassemble packet payload using sorted seq_nums
            data += window[seq_num]
        return data

    def send_ack(self):
        """
        Transmits an ACK pkt.
        """

        ack_pkt = self.create_tcp_pkt()
        ack_pkt.ack = True
        self.send_pkt(ack_pkt)

    def send_pkt(self, tcp_pkt: TCPPacket):
        """
        Transmits a pkt.

        :param tcp_pkt: the TCP pkt
        """
        self.last_pkt = tcp_pkt
        ip_pkt = IPPacket(src=self.src_host, dst=self.dst_host, data=tcp_pkt.pack())
        ip_pkt_raw = ip_pkt.pack()
        bytes_sent = self.send_sock.sendto(ip_pkt_raw, (self.dst_host, self.dst_port))
        assert len(ip_pkt_raw) == bytes_sent

    def recv_pkt(self) -> TCPPacket:
        """
        Performs error checking on incoming packets and handles retransmission as well as congestion control.

        :return: the TCP pkt
        """
        while True:
            try:
                raw_pkt = self.recv_sock.recv(MAX_PACKET_SIZE)
                ip_pkt = IPPacket.unpack(raw_pkt=raw_pkt)
                if ip_pkt and ip_pkt.protocol == socket.IPPROTO_TCP:
                    tcp_pkt = TCPPacket.unpack(ip_pkt=ip_pkt, raw_tcp_pkt=ip_pkt.data)
                    if tcp_pkt and tcp_pkt.dst_port == self.src_port:
                        if self.cwnd < MAX_CWND:
                            self.cwnd += 1

                        self.dst_adv_wnd = tcp_pkt.adv_wnd
                        self.counter = 3
                        self.seq_num = tcp_pkt.ack_num
                        return tcp_pkt
            except TimeoutError:
                if self.counter > 0:  # 3 retransmission max
                    self.send_pkt(self.last_pkt)  # retransmit the last pkt sent
                    self.counter -= 1  # 1 retransmission happened
                    # multiplicative decrease
                    self.cwnd = 1
                else:  # no response from the server for 3 straight times i.e. 3 minutes passed
                    print("Connection failed", file=sys.stderr)
                    self.close()
                    sys.exit(1)

    def create_tcp_pkt(self, payload: str = "") -> TCPPacket:
        """
        Builds a TCP pkt with the given payload.

        :param payload: the payload
        :return: the TCP pkt
        """

        tcp_pkt = TCPPacket(
            src_host=self.src_host,
            src_port=self.src_port,
            dst_host=self.dst_host,
            dst_port=self.dst_port,
            payload=payload,
        )
        tcp_pkt.seq_num = self.seq_num
        tcp_pkt.ack_num = self.ack_num
        tcp_pkt.adv_wnd = self.adv_wnd
        return tcp_pkt
