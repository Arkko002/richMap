from host_discovery.model.host_discovery_result import HostDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from scapy.layers.inet import IP, TCP


class XmasDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = IP(dst=target_ip)/TCP(flags="PUF")
        return super().send_probe_packet_and_get_result(packet, target_ip, 0, 3.0)
