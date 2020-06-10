from abc import abstractmethod

from richMap.abstract_base_scan import AbstractBaseScan
from richMap.host_discovery.host_discovery_result import HostDiscoveryResult


class AbstractHostDiscovery(AbstractBaseScan):
    @abstractmethod
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        pass

    def send_probe_packet_and_get_result(self, packet, target, port, timeout):
        results = self.soc.send_packet_and_return_result(packet, target, port, timeout)

        if results.icmp_res is None and results.soc_res is None:
            return HostDiscoveryResult(target, host_online=False)

        if results.icmp_res is not None or results.soc_res is not None:
            return HostDiscoveryResult(target, host_online=True)
