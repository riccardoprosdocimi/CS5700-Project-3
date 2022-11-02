# Riccardo
import socket
import IP
from utils import csum

IP_HEADER = bytes.fromhex('4500003c1c46400040060000ac100a63ac100a0c')


def main():
    # s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # create a raw socket
    # ip = IP.IPPacket('http://david.choffnes.com/classes/cs5700f22/project3.php')
    # ip.pack_fields()
    # s.sendto(ip.packet, get_source_address())
    csum(IP_HEADER)
    print(hex(csum(IP_HEADER)))








if __name__ == "__main__":
    main()
