class NetworkDiscoveryResult:
    """Contains information about network discovery on the targeted network"""
    def __init__(self, network_ip, host_discovery):
        """

        :param network_ip: IP of the targeted network with submask
        :param host_discovery: Type of the performed network discovery
        """
        self.network_ip = network_ip
        self.host_discovery = host_discovery
        self.host_results = []

