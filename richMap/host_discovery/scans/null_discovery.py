from host_discovery.model.host_discovery_result import HostDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from scapy.layers.inet import IP, TCP

#TODO
class NullDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        pass
