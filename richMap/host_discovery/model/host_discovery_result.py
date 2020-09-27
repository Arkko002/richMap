from host_discovery.error_handling.discovery_error import DiscoveryError


class HostDiscoveryResult:
    def __init__(self, ip, host_online: bool, error: DiscoveryError):
        self.ip = ip
        self.host_online = host_online
        self.error = error
