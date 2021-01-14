from richMap.host_discovery.model.host_discovery_result import HostDiscoveryResult
from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from scapy.layers.inet import IP, ICMP


class IcmpTimestampDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = IP(dst=target_ip)/ICMP(type=17)
        return super()._send_probe_packet_and_get_result(packet, target_ip)
