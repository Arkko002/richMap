import os
import socket
from scanner_socket.socket_type import SocketType


class SocketFactory:
    """"""
    def create_socket(self, soc_type: SocketType):
        if soc_type == SocketType.TCPRaw and os.getuid() != 0:
            raise PermissionError

        socket_switcher = {
            soc_type.TCP: self._get_tcp_socket(),
            soc_type.TCPRaw: self._get_tcp_raw_socket(),
            soc_type.ICMP: self._get_icmp_raw_socket()
        }

        return socket_switcher[soc_type]

    @staticmethod
    def _get_tcp_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)

    @staticmethod
    def _get_tcp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    @staticmethod
    def _get_icmp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
