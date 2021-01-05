import socket

from scapy.layers.inet import TCP, ICMP

from scanner_socket.socket_factory import SocketFactory
from scanner_socket.socket_type import SocketType


# TODO Validation method for ICMP packets, make sure they are responses to our TCP probing
class ScannerSocket:
    """
    Provides a layer of abstraction for low-level socket operations used in packet probing
    """

    def __init__(self, socket_type: SocketType, timeout: float = None):
        """

        :param socket_type: Protocol of the underlying socket that will be used in probing
        :param timeout: Timeout for awaiting socket's probe responses
        """
        if timeout is None:
            self.timeout = socket.getdefaulttimeout()
        else:
            self.timeout = timeout

        self.socket_type = socket_type

        self._open_sockets()

    def try_connecting_to_port(self, send_probe_packet, port):
        """ Tries to connect to port with TCP scanner_socket and returns true on success.
        Should only be used in TCP scan."""

        status = self.soc.connect_ex((send_probe_packet, port))

        if status == 0:
            self._open_sockets()
            return True
        else:
            return False

    def _open_sockets(self):
        """Creates and configures sockets with attributes provided on ScannerSocket initialization"""
        soc_factory = SocketFactory()
        self.soc = soc_factory.create_socket(self.socket_type)
        self.icmp_soc = soc_factory.create_socket(SocketType.ICMP)

        self.soc.settimeout(self.timeout)
        self.icmp_soc.settimeout(self.timeout)

    def close_sockets(self):
        """Closes underlying sockets"""
        self.soc.close()
        self.icmp_soc.close()

    def send_probe_packet(self, packet, target, port):
        """
        Sends the probe packet and returns the result packet on success.
        In case of a timeout retries sending the probe several more times.
        Returns None after several timeouts.

        :param packet: Probe packet to be sent
        :param target: IP of the targeted host
        :param port: Targeted Port
        :return: Result packet on success, None on failure
        """
        for i in range(3):
            self.soc.sendto(bytes(packet), (target, port))

            tcp_result = self._await_response(self.soc)
            icmp_result = self._await_response(self.icmp_soc)

            if tcp_result is not None:
                return TCP(tcp_result)

            if icmp_result is not None:
                return ICMP(icmp_result)

            self._open_sockets()

    @staticmethod
    def _await_response(soc):
        """
        Tries to receive incoming packet on the provided socket, returns None on the timeout.

        :param soc: Socket to receive from
        :return: Incoming packet on success, None on timeout
        """
        try:
            recv_packet = soc.recv(65535)
        except socket.timeout:
            return None
        return recv_packet
