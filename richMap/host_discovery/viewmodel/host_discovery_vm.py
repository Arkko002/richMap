from host_discovery.model.host_discovery_result import HostDiscoveryResult


class HostDiscoveryViewModel:
    def __init__(self, host_discovery_result: HostDiscoveryResult):
        self.ip = host_discovery_result.ip
        self.host_online_str = "Online" if host_discovery_result.host_online else "Offline"
        self.host_online = host_discovery_result.host_online

    def __str__(self):
        return f"{self.ip} - {self.host_online_str}"
