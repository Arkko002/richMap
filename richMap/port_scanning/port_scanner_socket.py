from richMap.port_scanning.port_scanner import SocketType
from richMap.port_scanning.socket_factory import SocketFactory


class PortScannerSocket:
    def __init__(self, socket_type: SocketType):
        self.soc = self.__get_raw_socket(socket_type)
        self.icmp_soc = self.__get_raw_socket(SocketType.ICMP)

    def send_packet_and_return_result(self, packet, target, port):
        return self.__send_probe_packet(packet, target, port)

    # TODO Thread for each socket
    @staticmethod
    def __await_response(socket):
        """Returns None if socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = socket.recv(65535)
        except socket.timeout:
            return None
        return recv_packet

    def __send_probe_packet(self, packet, target, port):
        """Resend's the probe packet, returns the response packets or None in case of no response"""

        for i in range(3):
            self.soc.sendto(packet, (target, port))
            tcp_result = self.__await_response(self.soc)
            icmp_result = self.__await_response(self.icmp_soc)
            if tcp_result is not None or icmp_result is not None:
                return tcp_result, icmp_result

    @staticmethod
    def __get_raw_socket(socket_type: SocketType):
        soc_factory = SocketFactory()
        return soc_factory.create_raw_socket(socket_type)
