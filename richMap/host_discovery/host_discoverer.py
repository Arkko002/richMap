import ipaddress

# TODO ICMP Ping, TCP SYN/Fin/Null/XMAS Ping, UDP Ping, IP Ping, Reverse DNS
from host_discovery.model.network_discovery_result import NetworkDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from util.ip_util import verify_ipv4, verify_ipv6


class HostDiscoverer:
    """Main class that provides operations for host discovery"""

    def __init__(self, network_ip: str, host_discovery: AbstractHostDiscovery):
        """

        :param network_ip: IP of the targeted network with submask
        :param host_discovery: Type of the network mapping to be performed
        """
        if self._check_if_valid_address(network_ip) is False:
            pass
            # TODO Error handling, probably something better than just returning a string

        # TODO IPv6 support
        self.network_addresses = ipaddress.IPv4Network(network_ip)
        self.network_result = NetworkDiscoveryResult(network_ip, host_discovery)
        self.host_discovery = host_discovery

    def map_network(self) -> NetworkDiscoveryResult:
        """
        Starts mapping the network with attributes provided on class initialization.

        :return: NetworkDiscoveryResult which contains list of HostDiscoveryResults
        """
        self.network_result.host_results = (result for result in self._host_result_generator(self.network_addresses))
        
        return self.network_result
    
    @staticmethod
    def _check_if_valid_address(network_ip):
        return verify_ipv4(network_ip) or verify_ipv6(network_ip)

    def _host_result_generator(self, network_addresses):
        for ip in network_addresses:
            yield self.host_discovery.get_discovery_result(ip)

