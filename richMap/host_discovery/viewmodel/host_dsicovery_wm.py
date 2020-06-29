from richMap.host_discovery.model.host_discovery_result import HostDiscoveryResult
from richMap.host_discovery.viewmodel.discovery_error_vm import DiscoveryErrorViewModel


class HostDiscoveryViewModel:
    def __init__(self, host_discovery_result: HostDiscoveryResult):
        self.ip = host_discovery_result.ip
        self.host_online = "UP" if host_discovery_result.host_online else "DOWN"

        self.error = DiscoveryErrorViewModel(host_discovery_result.error)

    def __str__(self):
        return f"{self.ip} - {self.host_online} {self.error.}"