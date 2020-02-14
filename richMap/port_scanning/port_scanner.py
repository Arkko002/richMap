import re
import socket

from richMap.port_scanning.host_result import HostResult
from richMap.port_scanning.port_result import PortResult
from richMap.scanner_socket import ScannerSocket
from richMap.port_scanning.scan_types import ScanTypes
from richMap.port_scanning.socket_type import SocketType


class PortScanner(object):
    def __init__(self, target: str, scan_type: ScanTypes, scan, port_range):
        self.target = target
        self.scan_type = scan_type
        self.scan = scan
        self.port_range = port_range.split("-")

    def perform_scan(self):
        """Performs a scans on target with parameters provided on object initalisation.
        Returns HostResult object."""
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if r.match(self.target) is False:
            return "The given IP is not in the correct format"

        host_result = HostResult(self.target, self.scan_type)

        for port in range(int(self.port_range[0]), int(self.port_range[1]) + 1):
            # TODO timeout in scans switcher
            port_state = self.scan.get_scan_result(self.target, port, 3.0)
            port_result = PortResult(port, port_state)

            host_result.port_results.append(port_result)

        return host_result

    # TODO
    def _ip_protocol_scan(self, target: str, soc: socket, soc_icmp: socket):
        return



