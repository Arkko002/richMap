from abc import ABC, abstractmethod

from scanner_socket import ScannerSocket


class AbstractBaseScan(ABC):
    def __init__(self, soc: ScannerSocket):
        self.soc = soc

    def __del__(self):
        self.soc.close_sockets()

    @abstractmethod
    def send_probe_packet(self, packet, target, port, timeout):
        pass
