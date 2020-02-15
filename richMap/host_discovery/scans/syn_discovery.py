from richMap.host_discovery.host_discovery_result import HostDiscoveryResult
from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from richMap.util.packet_generator import PacketGenerator


class SynDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = PacketGenerator.generate_tcp_header(0, syn=1)
        return super().send_probe_packet_and_get_result(packet, target_ip, 0, 3.0)
