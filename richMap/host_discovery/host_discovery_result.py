class HostDiscoveryResult:
    def __init__(self, ip, host_online: bool):
        self.ip = ip
        self.host_online = host_online