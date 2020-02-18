from abc import ABC, abstractmethod

from richMap.scan_factories.socket_type import SocketType
from richMap.scanner_socket import ScannerSocket


class AbstractScannerFactory(ABC):
    @abstractmethod
    def get_scanner(self, scanner_type):
        pass