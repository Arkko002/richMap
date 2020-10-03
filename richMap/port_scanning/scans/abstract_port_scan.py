from abc import abstractmethod

from abstract_base_scan import AbstractBaseScan
from port_scanning.model.port_result import PortResult
from port_scanning.model.port_state import PortState
from scapy.layers.inet import TCP


class AbstractPortScan(AbstractBaseScan):
    @abstractmethod
    def get_scan_result(self, target, port, timeout) -> PortResult:
        pass

    def send_probe_packet(self, packet, target, port, timeout=None):
        """Sends probe packet, returns PortState if probe failed, otherwise returns TCP packet"""
        results = self.soc.send_probe_packet(packet, target, port, timeout)

        result_error = self.check_probe_errors(results)
        if result_error is not None:
            return result_error

        if results.tcp_res is not None:
            return TCP(results.tcp_res)

    def check_probe_errors(self, results):
        if results.icmp_res is None and results.tcp_res is None:
            return PortState.NoResponse

        # TODO Result based on ICMP code
        if results.icmp_res is not None:
            return PortState.Filtered

        return None
