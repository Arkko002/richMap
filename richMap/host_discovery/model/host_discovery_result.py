class HostDiscoveryResult:
    """Contains information of an attempt to contact an IP address on the targeted network"""
    def __init__(self, ip, host_online: bool):
        """

        :param ip: Targeted IP
        :param host_online: Whether the node can be considered online
        """
        self.ip = ip
        self.host_online = host_online
