class NetworkDiscoveryResult:
    def __init__(self, network_ip, host_discovery_type):
        self.network_ip = network_ip
        self.host_discovery_type = host_discovery_type
        self.host_results = []

    def return_online_hosts(self):
        online_hosts = []
        for host in self.host_results:
            if host.host_online:
                online_hosts.append(host)

        return online_hosts
