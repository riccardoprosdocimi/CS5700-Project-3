# Riccardo
import socket


def csum(sent_message, nbytes):
    """
    Generic checksum calculation function.

    :param sent_message:
    :param nbytes:
    :return:
    """

    checksum = 0
    while nbytes > 1:
        checksum += sent_message
        nbytes -= 2
    if nbytes == 1:
        oddbyte = sent_message
        checksum += oddbyte
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    checksum = ~checksum
    return checksum


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # create a raw socket






if __name__ == "__main__":
    main()
