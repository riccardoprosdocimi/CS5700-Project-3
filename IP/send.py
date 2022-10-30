# Riccardo
import socket
import IP


def get_source_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('10.0.0.0', 0))
    source_address, port = socket.inet_aton(s.getsockname())
    s.close()
    return source_address, port


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # create a raw socket
    ip = IP.IPHeader('http://david.choffnes.com/classes/cs5700f22/project3.php')
    ip.package_fields()
    s.sendto(ip.raw, get_source_address())







if __name__ == "__main__":
    main()
