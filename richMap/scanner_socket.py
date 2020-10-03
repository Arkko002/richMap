import socket
from collections import namedtuple

from factories.socket_factory import SocketFactory
from factories.socket_type import SocketType


# TODO Validation method for ICMP packets, make sure they are responses to our TCP probing
class ScannerSocket:
    def __init__(self, socket_type: SocketType):
        soc_factory = SocketFactory()

        self.soc = soc_factory.create_socket(socket_type)
        self.icmp_soc = soc_factory.create_socket(socket_type.ICMP)

    def try_connecting_to_port(self, send_probe_packet, port):
        """ Tries to connect to port with TCP socket and returns true on success.
        Should only be used in TCP scan."""

        status = self.soc.connect_ex((send_probe_packet, port))

        if status == 0:
            return True
        else:
            return False

    def close_sockets(self):
        self.soc.close()
        self.icmp_soc.close()

    def send_probe_packet(self, packet, target, port, timeout):
        """Sends the probe packet, returns the response packets or None in case of no response"""

        self.soc.settimeout(timeout)
        self.icmp_soc.settimeout(timeout)

        for i in range(3):
            self.soc.sendto(packet, (target, port))

            tcp_result = self._await_response(self.soc)
            icmp_result = self._await_response(self.icmp_soc)

            if tcp_result is not None or icmp_result is not None:
                SocketResponses = namedtuple('Responses', ['tcp_res', "icmp_res"])
                return SocketResponses(tcp_result, icmp_result)

    # TODO Thread for each socket
    @staticmethod
    def _await_response(soc):
        """Returns None if socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = soc.recv(65535)
        except soc.timeout:
            return None
        return recv_packet
