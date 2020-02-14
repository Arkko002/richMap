from abc import ABC, abstractmethod

from richMap.scanner_socket import ScannerSocket


class AbstractBaseScanner(ABC):
    def __init__(self, soc: ScannerSocket):
        self.soc = soc

    def __del__(self):
        self.soc.close_sockets()

    @abstractmethod
    def send_probe_packet_and_get_result(self, packet, target, port, timeout):
        pass
