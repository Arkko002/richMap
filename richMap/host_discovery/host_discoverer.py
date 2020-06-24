import ipaddress
import re

# TODO ICMP Ping, TCP SYN/Fin/Null/XMAS Ping, UDP Ping, IP Ping, Reverse DNS
from richMap.host_discovery.network_discovery_result import NetworkDiscoveryResult


class HostDiscoverer():
    """Used to discover live hosts on the network"""

    def __init__(self, network_ip: str, network_result: NetworkDiscoveryResult, host_discovery: AbstractHostDiscovery):
        if self._check_if_valid_address(network_ip) is False:
            # TODO Error handling, probably something better than just returning a string

        # TODO IPv6 support
        self.network_addresses = ipaddress.IPv4Network(network_ip)
        self.network_result = network_result
        self.host_discovery = host_discovery

    def map_network(self):
        self.network_result.host_results = (result for result in self._host_result_generator(self.network_addresses))
        
        return self.network_result
    
    def _check_if_valid_address(network_ip):
        """Performs a specified type of scan on a given IP range"""
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if not r.match(self.network_ip):
            return False 

        return True

    def _host_result_generator(self, network_addresses):
        for ip in network_addresses:
            yield self.host_discovery.get_discovery_result(ip)

