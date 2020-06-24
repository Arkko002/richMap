from richMap.port_scanning.model.host_result import HostResult
from richMap.port_scanning.model.scan_types import ScanTypes
from richMap.port_scanning.viewmodel.port_result_viewmodel import PortResultViewModel


class HostResultViewModel:
    def __init__(self, host_result: HostResult):
        self.target = "Target IP: " + host_result.target_ip
        self.scan_type = host_result.scan_type
        self.scan_type_str = self._convert_scan_type_to_str(host_result.scan_type)
        self.port_results = self._convert_port_results(host_result.port_results)

    @staticmethod
    def _convert_scan_type_to_str(scan_type: ScanTypes):
        scan_type_switcher = {
            ScanTypes.T: "TCP Scan",
            ScanTypes.S: "SYN Scan",
            ScanTypes.U: "UDP Scan",
            ScanTypes.A: "ACK Scan",
            ScanTypes.F: "FIN Scan",
            ScanTypes.X: "Xmas Scan",
            ScanTypes.N: "Null Scan",
            ScanTypes.M: "Maimon's Scan",
            ScanTypes.W: "Window Scan"
        }

        return scan_type_switcher[scan_type]

    @staticmethod
    def _convert_port_results(port_results: []):
        return [PortResultViewModel(port_result) for port_result in port_results]
