from abc import ABC, abstractmethod

from richMap.port_scanning.model.scan_types import ScanType


class AbstractHostResultFactory(ABC):
    @abstractmethod
    def get_host_result(self, target_ip, scan_type: ScanType):
        pass
