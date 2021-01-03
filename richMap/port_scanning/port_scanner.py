from util.ip_util import verify_ipv4, verify_ipv6
from port_scanning.model.host_result import HostResult


class PortScanner:
    """Main class providing operations for port scanning"""
    def __init__(self, target, scan, port_range):
        """

        :param target: IP of the targeted host
        :param scan: Type of the scan to be performed
        :param port_range: Range of ports to be scanned
        """
        if self._check_if_valid_address(target) is False:
            # TODO Error handling
            pass

        self.host_result = HostResult(target, port_range, scan)
        self.target = target

    def perform_scan(self) -> HostResult:
        """
        Starts scanning the ports with attributes provided on class initialization.

        :return: HostResult which contains list of PortResults
        """
        for port in range(self.host_result.port_range[0], self.host_result.port_range[1] + 1):
            self.host_result.port_results.append(self.host_result.scan.get_scan_result(self.target, port, 3.0))

        return self.host_result

    @staticmethod
    def _check_if_valid_address(target):
        return verify_ipv4(target) or verify_ipv6(target)
