import socket
import array


def get_nw_interface_name() -> str:
    prefixes = ("enp", "eth", "wlp")

    for _, int_name in socket.if_nameindex():
        for prefix in prefixes:
            if int_name.startswith(prefix):
                return int_name

    raise ValueError("Cannot find a valid network interface")


def get_local_ip():
    from subprocess import check_output
    return check_output(['hostname', '-I']).decode().strip()


def csum(packet):
    if len(packet) % 2 != 0:
        packet += b'\0'
    checksum = sum(
        array.array("H", packet)  # create array of fixed element types to calculate sum of 16-bit words
    )
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    return ~checksum & 0xFFFF


# def csum(self, sent_message, nbytes):
#     """
#     Generic checksum calculation function.
#
#     :param sent_message:
#     :param nbytes:
#     :return:
#     """
#
#     while nbytes > 1:
#         self.checksum += sent_message
#         nbytes -= 2
#     if nbytes == 1:
#         oddbyte = sent_message
#         self.checksum += oddbyte
#     self.checksum = (self.checksum >> 16) + (self.checksum & 0xFFFF)
#     self.checksum = self.checksum + (self.checksum >> 16)
#     self.checksum = ~self.checksum
#     return self.checksum
