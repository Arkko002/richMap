class NetworkDiscoveryResult:
    def __init__(self, network_ip, host_discovery_type):
        self.network_ip = network_ip
        self.host_discovery_type = host_discovery_type
        self.host_results = []

