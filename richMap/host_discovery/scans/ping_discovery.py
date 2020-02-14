import os

from richMap.host_discovery.host_discovery_result import HostDiscoveryResult
from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery


class PingDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip):
        response = os.system("ping -c 1 " + target_ip)
        if response == 0:
            return HostDiscoveryResult(target_ip, host_online=True)
