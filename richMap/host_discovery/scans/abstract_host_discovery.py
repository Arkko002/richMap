from abc import abstractmethod

from abstract_base_scan import AbstractBaseScan
from host_discovery.model.host_discovery_result import HostDiscoveryResult


class AbstractHostDiscovery(AbstractBaseScan):
    """Defines common operations used by host discovery techniques"""
    @abstractmethod
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        """
        Returns the result of probing a specified IP

        :param target_ip: Targeted IP
        """
        pass

    def send_probe_packet_and_get_result(self, packet, target, port, timeout):
        results = self.soc.send_probe_packet(packet, target, port, timeout)

        if results.icmp_res is None and results.soc_res is None:
            return HostDiscoveryResult(target, host_online=False)

        if results.icmp_res is not None or results.soc_res is not None:
            return HostDiscoveryResult(target, host_online=True)
