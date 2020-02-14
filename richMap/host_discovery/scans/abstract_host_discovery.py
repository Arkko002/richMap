from abc import ABC, abstractmethod

from richMap.host_discovery.host_discovery_result import HostDiscoveryResult


class AbstractHostDiscovery(ABC):
    @abstractmethod
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        pass