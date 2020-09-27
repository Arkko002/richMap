from enum import Enum


class SocketType(Enum):
    Error = 0
    TCP = 1
    TCPRaw = 2
    ICMP = 3
