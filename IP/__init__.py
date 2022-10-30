from binascii import hexlify
import socket
import struct


class IPPacket:
    def __init__(self, source, destination, data):
        self.version = 4
        self.header_length = 5
        self.service_type = 0
        self.total_length = len(data) + 20
        self.identification = 0
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 255
        self.protocol = 6
        self.checksum = 0
        self.source = source
        self.destination = destination

    @staticmethod
    def from_bytes(raw_pkt):
        raw_ip_header = raw_pkt[14:35]
        total_length_raw = raw_ip_header[2:4]
        (total_length,) = struct.unpack("!h", total_length_raw)
        data = raw_pkt[35 : 35 + total_length - 20]  # header length = 20

        pkt_id_raw = raw_ip_header[5:7]
        (pkt_id,) = struct.unpack("!h", pkt_id_raw)

        ttl_raw = raw_ip_header[9:10]
        (ttl,) = struct.unpack("!c", ttl_raw)
        ttl = int(hexlify(ttl), base=16)

        protocol_raw = raw_ip_header[10:11]
        (protocol,) = struct.unpack("!c", protocol_raw)
        protocol = int(hexlify(protocol), base=16)

        checksum_raw = raw_ip_header[11:13]
        (checksum,) = struct.unpack("!h", checksum_raw)

        src_ip_raw = raw_ip_header[13:17]
        src_ip = socket.inet_ntoa(src_ip_raw)

        dst_ip_raw = raw_ip_header[17:21]
        dst_ip = socket.inet_ntoa(dst_ip_raw)

        ip_packet = IPPacket(src_ip, dst_ip, data)
        ip_packet.identification = pkt_id
        ip_packet.ttl = ttl
        ip_packet.protocol = protocol
        ip_packet.checksum = checksum

        return ip_packet
