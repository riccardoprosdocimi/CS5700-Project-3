import socket
from random import randint
from typing import Optional

from utils import get_local_ip
from tcp_pkt import TCPPacket
from ip_pkt import IPPacket


class TCPSocket:
    def __init__(self, dst_host: str):
        self.adv_wnd = 65535
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
        self.dst_seq_num = 0

        self.src_host = get_local_ip()
        self.src_port = randint(1025, 65535)

    def handshake(self) -> bool:
        syn_pkt = self.new_tcp_pkt()
        syn_pkt.syn = True
        self.send(syn_pkt)

        recvd_pkt = self.recv()
        if recvd_pkt and self.is_syn_ack(recvd_pkt):
            self.dst_seq_num = recvd_pkt.seq_num
            ack_pkt = self.new_tcp_pkt()
            ack_pkt.ack = True
            self.send(ack_pkt)
            return True
        else:
            # TODO: Handle error when SYN/ACK is not received
            return False

    def send(self, tcp_pkt: TCPPacket):
        ip_pkt = IPPacket(
            src=self.src_host, dst=self.dst_host, data=tcp_pkt.pack_fields()
        )
        ip_pkt_raw = ip_pkt.pack_fields()

        bytes_sent = self.send_sock.sendto(ip_pkt_raw, (self.dst_host, self.dst_port))
        assert len(ip_pkt_raw) == bytes_sent

    def recv(self) -> Optional[TCPPacket]:  # returns None on timeout
        while True:
            try:
                raw_pkt, _ = self.recv_sock.recvfrom(65535)
                ip_pkt = IPPacket.unpack(raw_pkt=raw_pkt)

                if ip_pkt.protocol == socket.IPPROTO_TCP:
                    tcp_pkt = TCPPacket.unpack(ip_pkt=ip_pkt, raw_tcp_pkt=ip_pkt.data)
                    if tcp_pkt.dst_port == self.src_port:
                        return tcp_pkt
            except socket.timeout:
                return None

    def new_tcp_pkt(self) -> TCPPacket:
        pkt = TCPPacket(
            src_host=self.src_host,
            src_port=self.src_port,
            dst_host=self.dst_host,
            dst_port=self.dst_port,
        )

        pkt.seq_num = randint(0, 2**32 - 1)
        pkt.adv_wnd = self.adv_wnd
        return pkt

    @staticmethod
    def is_syn_ack(tcp_pkt: TCPPacket) -> bool:
        return tcp_pkt.syn and tcp_pkt.ack
