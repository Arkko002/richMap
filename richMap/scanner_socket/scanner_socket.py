import socket
from collections import namedtuple

from scapy.layers.inet import TCP, ICMP

from factories.socket_factory import SocketFactory
from factories.socket_type import SocketType


# TODO Validation method for ICMP packets, make sure they are responses to our TCP probing
class ScannerSocket:
    def __init__(self, socket_type: SocketType, timeout=None):
        if timeout is None:
            self.timeout = socket.getdefaulttimeout()
        else:
            self.timeout = timeout

        self.socket_type = socket_type

        self.open_sockets()

    def try_connecting_to_port(self, send_probe_packet, port):
        """ Tries to connect to port with TCP scanner_socket and returns true on success.
        Should only be used in TCP scan."""

        status = self.soc.connect_ex((send_probe_packet, port))

        if status == 0:
            self.open_sockets()
            return True
        else:
            return False

    def open_sockets(self):
        soc_factory = SocketFactory()
        self.soc = soc_factory.create_socket(self.socket_type)
        self.icmp_soc = soc_factory.create_socket(SocketType.ICMP)

        self.soc.settimeout(self.timeout)
        self.icmp_soc.settimeout(self.timeout)

    def close_sockets(self):
        self.soc.close()
        self.icmp_soc.close()

    def send_probe_packet(self, packet, target, port):
        """Sends the probe packet, returns the response packets or None in case of no response"""

        for i in range(3):
            self.soc.sendto(bytes(packet), (target, port))

            tcp_result = self._await_response(self.soc)
            icmp_result = self._await_response(self.icmp_soc)

            if tcp_result is not None:
                return TCP(tcp_result)

            if icmp_result is not None:
                return ICMP(icmp_result)

            self.open_sockets()

    @staticmethod
    def _await_response(soc):
        """Returns None if scanner_socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = soc.recv(65535)
        except socket.timeout:
            return None
        return recv_packet
