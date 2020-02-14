import os
import re
import socket
import ipaddress

from richMap.host_discovery.mapping_types import MappingTypes
from richMap.util.packet_generator import PacketGenerator
import random
from time import sleep

# TODO ICMP Ping, TCP SYN/Fin/Null/XMAS Ping, UDP Ping, IP Ping, Reverse DNS
class Netmapper(object):
    """Used to discover live hosts on the network"""

    def __init__(self, network_ip: str, host_discovery_type, host_discovery, net_interface: str = None):
        self.network_ip = network_ip
        self.host_discovery_type = host_discovery_type
        self.host_discovery = host_discovery

        if net_interface is None:
            self.net_interface = self.__get_default_interface()
        else:
            self.net_interface = net_interface

        self.soc = self.__create_scan_socket()

    def __del__(self):
        self.soc.close()

    # TODO Make all of this DRY
    # TODO Make net_interface optional
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

    def _await_arp_response(self):
        try:
            rec_packet = self.soc.recv(1024)
        except socket.timeout:
            return
        return rec_packet

    @staticmethod
    def __get_default_interface():
        interfaces = os.listdir("/sys/class/net")
        return interfaces[0]

    def __create_scan_socket(self, scan_type: str):
        if "A" in scan_type:
            self.soc = 

            if scan_type == "As":
            
