from enum import Enum


class TcpFlags(Enum):
    CWR = 0
    ECE = 1
    URG = 2
    ACK = 3
    PSH = 4
    RST = 5
    SYN = 6
    FIN = 7


class TcpResponsePacket:
    def __init__(self, tcp_flags, tcp_header):
        self.tcp_flags = tcp_flags
        self.tcp_header = tcp_header

    def get_window_size(self):
        return self.tcp_header[6]