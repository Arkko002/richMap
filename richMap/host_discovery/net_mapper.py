import re
import ipaddress

from richMap.host_discovery.mapping_types import MappingTypes


# TODO ICMP Ping, TCP SYN/Fin/Null/XMAS Ping, UDP Ping, IP Ping, Reverse DNS
class Netmapper(object):
    """Used to discover live hosts on the network"""

    def __init__(self, network_ip: str, host_discovery_type: MappingTypes, host_discovery):
        self.network_ip = network_ip
        self.host_discovery_type = host_discovery_type
        self.host_discovery = host_discovery

    def map_network(self):
        """Performs a specified type of scan on a given IP range"""
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")
        if not r.match(self.network_ip):
            return "The given IP is not in the correct format"

        return_list = []

        for ip in ipaddress.IPv4Network(self.network_ip):
            host_result = self.host_discovery(ip)
            return_list.append(host_result)

        return return_list
