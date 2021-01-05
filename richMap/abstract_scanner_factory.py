from abc import ABC, abstractmethod


class AbstractScannerFactory(ABC):
    @abstractmethod
    def get_scanner(self, scanner_type, timeout):
        pass
