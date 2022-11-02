import socket


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