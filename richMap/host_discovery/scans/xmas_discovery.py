from host_discovery.model.host_discovery_result import HostDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from scapy.all import IP, TCP


class XmasDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = PacketGenerator.generate_tcp_header(0, fin=1, urg=1, psh=1)
        return super().send_probe_packet_and_get_result(packet, target_ip, 0, 3.0)
