import os
import socket
from richMap.factories.socket_type import SocketType


class SocketFactory:
    def create_socket(self, soc_type: SocketType):
        if os.getuid() != 0:
            return "You need administrator rights to run this scan"

        socket_switcher = {
            soc_type.TCP: self._get_tcp_socket(),
            soc_type.TCPRaw: self._get_tcp_raw_socket(),
            soc_type.UDP: self._get_udp_raw_socket(),
            soc_type.ICMP: self._get_icmp_raw_socket()
        }

        return socket_switcher[soc_type]

    @staticmethod
    def _get_tcp_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    @staticmethod
    def _get_udp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    @staticmethod
    def _get_tcp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    @staticmethod
    def _get_icmp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)