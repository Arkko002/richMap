import ipaddress
import re

# TODO ICMP Ping, TCP SYN/Fin/Null/XMAS Ping, UDP Ping, IP Ping, Reverse DNS
from richMap.host_discovery.network_discovery_result import NetworkDiscoveryResult


class Netmapper(object):
    """Used to discover live hosts on the network"""

    def __init__(self, network_ip: str, network_result: NetworkDiscoveryResult, host_discovery):
        self.network_ip = network_ip
        self.network_result = network_result
        self.host_discovery = host_discovery

    def map_network(self):
        """Performs a specified type of scan on a given IP range"""
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")
        if not r.match(self.network_ip):
            return "The given IP is not in the correct format"

        for ip in ipaddress.IPv4Network(self.network_ip):
            host_result = self.host_discovery(ip)
            self.network_result.host_results.append(host_result)

        return self.network_result.host_results
