from richMap.host_discovery.model.host_discovery_result import HostDiscoveryResult
from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from scapy.layers.inet import IP, TCP


class SynDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = IP(dst=target_ip)/TCP(flags="S", port=80)
        return super()._send_probe_packet_and_get_result(packet)
