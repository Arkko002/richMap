from abc import abstractmethod

from abstract_base_scan import AbstractBaseScan
from port_scanning.model.port_result import PortResult
from port_scanning.model.port_state import PortState
from scapy.layers.inet import TCP


class AbstractPortScan(AbstractBaseScan):
    @abstractmethod
    def get_scan_result(self, target, port, timeout) -> PortResult:
        pass

    def send_probe_packet(self, packet, target, port):
        """Sends probe packet, returns PortState if probe failed, otherwise returns TCP packet"""
        results = self.soc.send_probe_packet(packet, target, port)

        result_error = self.check_probe_errors(results)
        if result_error is not None:
            return result_error

        return results

    def check_probe_errors(self, results):
        if results is None:
            return PortState.NoResponse

        # TODO ICMP Error handling based on codes

        # if results.icmp_res is None and results.tcp_res is None:
        #     return PortState.NoResponse
        # if results.icmp_res is not None:
        #     return PortState.Filtered