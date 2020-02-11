import os
import socket
from richMap.port_scanning.port_scanner import SocketType


class SocketFactory:
    @staticmethod
    def create_tcp_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def create_raw_socket(self, soc_type: SocketType):
        if os.getuid() != 0:
            return "You need administrator rights to run this scan"

        socket_switcher = {
            SocketType.TCP: self.__get_tcp_raw_socket(),
            SocketType.UDP: self.__get_udp_raw_socket(),
            SocketType.ICMP: self.__get_icmp_raw_socket()
        }

        return socket_switcher[soc_type]

    @staticmethod
    def __get_udp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    @staticmethod
    def __get_tcp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    @staticmethod
    def __get_icmp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)