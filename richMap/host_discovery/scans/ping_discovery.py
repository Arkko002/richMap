import os

from host_discovery.model.host_discovery_result import HostDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery


class PingDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        response = os.system("ping -c 1 " + target_ip)
        if response == 0 or response == 2:
            return HostDiscoveryResult(target_ip, host_online=True)
        else:
            return HostDiscoveryResult(target_ip, host_online=False)
