from richMap.port_scanning.port_result import PortResult, PortState
from richMap.port_scanning.scan_types import ScanTypes


class HostResult:
    def __init__(self, target_ip, scan_type: ScanTypes):
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_results = []

    def append_port_result(self, port, port_state: PortState):
        port_result = PortResult(port, port_state)

        self.port_results.append(port_result)

    def return_positive_port_results(self):
        positive_results = []
        for result in self.port_results:
            if result.port_open is True:
                positive_results.append(result)

        return positive_results
