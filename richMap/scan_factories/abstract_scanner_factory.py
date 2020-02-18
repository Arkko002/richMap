from abc import ABC, abstractmethod

from richMap.abstract_base_scanner import AbstractBaseScanner


class AbstractScannerFactory(ABC):
    @abstractmethod
    def get_scanner(self, scanner_type, soc):
        pass