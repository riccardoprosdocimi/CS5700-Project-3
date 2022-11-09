import socket
from random import randint
from typing import Optional
from utils import get_local_ip
from tcp_pkt import TCPPacket
from ip_pkt import IPPacket

LOCAL_HOST = "127.0.0.1"


class TCPSocket:
    def __init__(self, dst_host: str):
        self.adv_wnd = 65535
        self.rto = 60  # seconds

        self.recv_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
        )
        self.recv_sock.settimeout(self.rto)
        # TODO: try catch block to catch timeout exception

        self.send_sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )

        self.dst_host = socket.gethostbyname(dst_host)
        self.dst_port = 80  # HTTP

        self.src_host = get_local_ip()
        self.src_port = randint(1025, 65535)
        # self.is_port_open()

        self.seq_num = randint(0, 2**32 - 1)
        self.ack_num = 0

    def is_port_open(self):
        if self.send_sock.connect_ex((LOCAL_HOST, self.src_port)) != 0:
            self.src_port = randint(1025, 65535)

    def connect(self) -> bool:
        # 3-way handshake
        syn_pkt = self.new_tcp_pkt()
        syn_pkt.syn = True
        self.send_pkt(syn_pkt)

        recvd_pkt = self.recv_pkt()
        if recvd_pkt and recvd_pkt.syn and recvd_pkt.ack:
            self.send_ack()
            return True
        else:
            # TODO: Handle error when SYN/ACK is not received
            # Probably want to close connection using FIN/ACK
            return False

    def close(self):
        fin_ack_pkt = self.new_tcp_pkt()
        fin_ack_pkt.fin = True
        fin_ack_pkt.ack = True
        self.send_pkt(fin_ack_pkt)

    def send(self, http_pkt: str):
        tcp_pkt = self.new_tcp_pkt(http_pkt=http_pkt)
        tcp_pkt.ack = True
        self.send_pkt(tcp_pkt=tcp_pkt)

    def recv(self):
        window = {}

        while True:
            recvd_pkt = self.recv_pkt()
            if not recvd_pkt:
                # TODO handle error
                print("Handle error when packet is null")
                return

            if (
                recvd_pkt.ack
                and recvd_pkt.seq_num not in window
                and recvd_pkt.payload
            ):
                window[recvd_pkt.seq_num] = recvd_pkt.payload
                self.send_ack()

                if recvd_pkt.fin or recvd_pkt.rst:
                    self.close()
                    break

        sorted_seq_nums = sorted(window.keys())
        data = bytearray()
        for seq_num in sorted_seq_nums:
            data += window[seq_num]

        return data

    def send_ack(self):
        ack_pkt = self.new_tcp_pkt()
        ack_pkt.ack = True
        self.send_pkt(ack_pkt)

    def send_pkt(self, tcp_pkt: TCPPacket):
        ip_pkt = IPPacket(
            src=self.src_host, dst=self.dst_host, data=tcp_pkt.pack()
        )
        ip_pkt_raw = ip_pkt.pack_fields()

        bytes_sent = self.send_sock.sendto(ip_pkt_raw, (self.dst_host, self.dst_port))
        assert len(ip_pkt_raw) == bytes_sent

    def recv_pkt(self) -> Optional[TCPPacket]:  # returns None on timeout
        while True:
            try:
                raw_pkt, _ = self.recv_sock.recvfrom(65535)
                ip_pkt = IPPacket.unpack(raw_pkt=raw_pkt)

                if ip_pkt.protocol == socket.IPPROTO_TCP:
                    tcp_pkt = TCPPacket.unpack(ip_pkt=ip_pkt, raw_tcp_pkt=ip_pkt.data)
                    if tcp_pkt.dst_port == self.src_port:
                        self.seq_num = tcp_pkt.ack_num
                        self.ack_num = tcp_pkt.seq_num + 1
                        return tcp_pkt
            except socket.timeout:
                return None

    def new_tcp_pkt(self, http_pkt: str = "") -> TCPPacket:
        pkt = TCPPacket(
            src_host=self.src_host,
            src_port=self.src_port,
            dst_host=self.dst_host,
            dst_port=self.dst_port,
            payload=http_pkt,
        )

        pkt.seq_num = self.seq_num
        pkt.ack_num = self.ack_num
        pkt.adv_wnd = self.adv_wnd
        return pkt
