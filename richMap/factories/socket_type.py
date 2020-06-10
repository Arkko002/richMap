from enum import Enum


class SocketType(Enum):
    Error = 0
    UDP = 1
    TCP = 2
    TCPRaw = 3
    ICMP = 4
