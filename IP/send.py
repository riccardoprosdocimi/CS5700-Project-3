# Riccardo
import socket
import IP


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # create a raw socket
    ip = IP.IPPacket('http://david.choffnes.com/classes/cs5700f22/project3.php')
    ip.pack_fields()
    s.sendto(ip.packet, get_source_address())







if __name__ == "__main__":
    main()
