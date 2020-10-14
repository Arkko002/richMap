from util.ip_util import verify_ipv4, verify_ipv6
from port_scanning.model.host_result import HostResult


class PortScanner(object):
    def __init__(self, target, scan, port_range):
        if self._check_if_valid_address(target) is False:
            # TODO Error handling
            pass

        self.host_result = HostResult(target, port_range, scan)
        self.current_port = self.host_result.port_range[0]
        
    def perform_scan(self):
        """Performs a scans on target with parameters provided on object initialization.
        Returns HostResult object."""

        port_results = (result for result in self._port_result_generator(self.host_result.target,
                                                                         self.host_result.port_range, 3.0))
        self.host_result.port_results = port_results

        return self.host_result

    @staticmethod
    def _check_if_valid_address(target):
        return verify_ipv4(target) or verify_ipv6(target)

    def _port_result_generator(self, target, port_range, timeout):
        for port in range(port_range[0], port_range[1]):
            self.current_port = port
            yield self.host_result.scan.get_scan_result(target, port, timeout)
