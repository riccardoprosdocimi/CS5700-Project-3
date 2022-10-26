# Riccardo
import socket


def csum(sent_message, nbytes):
    """
    Generic checksum calculation function.

    :param sent_message:
    :param nbytes:
    :return:
    """

    # 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation
    source_address = sent_message[0:nbytes]
    dest_address = sent_message[nbytes:2 * nbytes]
    placeholder = sent_message[2 * nbytes:3 * nbytes]
    protocol = sent_message[3 * nbytes: 4 * nbytes]
    tcp_length = sent_message[4 * nbytes:5 * nbytes]

    # calculating the binary sum of packets
    binary_sum = bin(int(source_address, 2) +
                     int(dest_address, 2) +
                     int(placeholder, 2) +
                     int(protocol, 2) +
                     int(tcp_length, 2))[2:]

    # adding the overflow bits
    if len(binary_sum) > nbytes:
        of_bits = len(binary_sum) - nbytes
        binary_sum = bin(int(binary_sum[0:of_bits], 2) +
                         int(binary_sum[of_bits:], 2))[2:]
    if len(binary_sum) < nbytes:
        binary_sum = '0' * (nbytes - len(binary_sum)) + binary_sum

    # calculating the complement of sum
    checksum = ''
    for i in binary_sum:
        if i == '1':
            checksum += '0'
        else:
            checksum += '1'

    return checksum


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)  # create a raw socket






if __name__ == "__main__":
    main()
