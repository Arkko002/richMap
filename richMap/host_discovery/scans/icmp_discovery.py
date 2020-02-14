from richMap.host_discovery.host_discovery_result import HostDiscoveryResult
from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery


class IcmpDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        pass