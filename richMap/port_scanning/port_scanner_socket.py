import socket
from collections import namedtuple

from richMap.port_scanning.socket_factory import SocketFactory
from richMap.port_scanning.socket_type import SocketType


class PortScannerSocket:
    def __init__(self, socket_type: SocketType):
        soc_factory = SocketFactory()

        if socket_type.TCPRaw:
            self.soc = soc_factory.create_socket(socket_type.TCPRaw)
        else:
            self.soc = soc_factory.create_socket(socket_type.TCP)
        self.icmp_soc = soc_factory.create_socket(socket_type.ICMP)

    def try_connecting_to_port(self, target, port):
        """ Tries to connect to port with TCP socket and returns true on success.
        Should only be used in TCP scan."""

        status = self.soc.connect_ex((target, port))

        if status == 0:
            self.soc.shutdown(socket.SHUT_RDWR)
            return True
        else:
            return False

    def send_packet_and_return_result(self, packet, target, port, timeout):
        return self.__send_probe_packet(packet, target, port, timeout)

    def close_sockets(self):
        self.soc.close()
        self.icmp_soc.close()

    def __send_probe_packet(self, packet, target, port, timeout):
        """Resend's the probe packet, returns the response packets or None in case of no response"""

        self.soc.settimeout(timeout)
        self.icmp_soc.settimeout(timeout)

        for i in range(3):
            self.soc.sendto(packet, (target, port))
            tcp_result = self.__await_response(self.soc)
            icmp_result = self.__await_response(self.icmp_soc)
            if tcp_result is not None or icmp_result is not None:
                SocketResponses = namedtuple('Responses', ['soc_res', "icmp_res"])
                return SocketResponses(tcp_result, icmp_result)

    # TODO Thread for each socket
    @staticmethod
    def __await_response(socket):
        """Returns None if socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = socket.recv(65535)
        except socket.timeout:
            return None
        return recv_packet