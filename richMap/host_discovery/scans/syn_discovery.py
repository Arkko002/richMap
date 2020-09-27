from host_discovery.model.host_discovery_result import HostDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery


class SynDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = PacketGenerator.generate_tcp_header(0, syn=1)
        return super().send_probe_packet(packet, target_ip, 0, 3.0)
