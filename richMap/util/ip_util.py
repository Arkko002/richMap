import socket


def verify_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
        return False

    return True


def verify_ipv6(ip):
    try:
        socket.inet_pton(socket.AF_INET6, ip)
    except socket.error:
        return False

    return True
