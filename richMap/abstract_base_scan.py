from abc import ABC, abstractmethod

from richMap.port_scanning.model.scan_types import ScanTypes
from richMap.scanner_socket import ScannerSocket


class AbstractBaseScan(ABC):
    def __init__(self, soc: ScannerSocket, scan_type: ScanTypes):
        self.soc = soc
        self.scan_type = scan_type

    def __del__(self):
        self.soc.close_sockets()

    @abstractmethod
    def send_probe_packet_and_get_result(self, packet, target, port, timeout):
        pass
