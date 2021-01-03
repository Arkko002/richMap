from abc import ABC

from scanner_socket.scanner_socket import ScannerSocket


class AbstractBaseScan(ABC):
    def __init__(self, soc: ScannerSocket):
        """

        :param soc: Socket that will be used for packet probing
        """
        self.soc = soc

    def __del__(self):
        self.soc.close_sockets()

    def send_probe_packet(self, packet, target, port):
        pass
