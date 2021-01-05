from abc import abstractmethod

from abstract_base_scan import AbstractBaseScan
from port_scanning.model.port_result import PortResult
from port_scanning.model.port_state import PortState
from scapy.layers.inet import TCP


class AbstractPortScan(AbstractBaseScan):
    """Defines common operations used by port scanning techniques"""
    @abstractmethod
    def get_scan_result(self, target, port, timeout: float) -> PortResult:
        """
        Returns the result of scanning the specified port

        :param target: IP of the targeted host
        :param port: Targeted port
        :param timeout: Timeout value for probe packets
        """
        pass

    def send_probe_packet(self, packet, target, port):
        """
        Sends the probe packet and validates return value.

        :param packet: Probe packet to be sent
        :param target: IP of the targeted host
        :param port: Targeted port
        :return: Result packet on success, or PortState describing the error on failure.
        """
        results = self.soc.send_probe_packet(packet, target, port)

        result_error = self._check_probe_errors(results)
        if result_error is not None:
            return result_error

        return results

    @staticmethod
    def _check_probe_errors(results):
        """
        Checks the result of probing for errors.

        :param results: Result returned by ScannerSocket
        :return: PortState describing the error, or None if no errors are detected
        """
        if results is None:
            return PortState.NoResponse

        # TODO ICMP Error handling based on codes

        # if results.icmp_res is None and results.tcp_res is None:
        #     return PortState.NoResponse
        # if results.icmp_res is not None:
        #     return PortState.Filtered