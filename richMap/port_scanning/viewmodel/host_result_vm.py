from richMap.port_scanning.model.host_result import HostResult
from richMap.port_scanning.model.scan_types import ScanType
from richMap.port_scanning.viewmodel.port_result_wm import PortResultViewModel
from richMap.port_scanning.error_handling.scanner_error import ScannerError


class HostResultViewModel:
    def __init__(self, host_result: HostResult):
        self.model_host_result = host_result

        self.target_str = "Target IP: " + host_result.target_ip
        self.scan_type_str = self._convert_scan_type_to_str(host_result.scan_type)
        self.port_result_vms = self._convert_port_results(host_result.port_results)

    def __str__(self):
        return f"Results of {self.scan_type_str} on {self.target_str}"

    @staticmethod
    def _convert_scan_type_to_str(scan_type: ScanType):
        scan_type_switcher = {
            ScanType.T: "TCP Scan",
            ScanType.S: "SYN Scan",
            ScanType.U: "UDP Scan",
            ScanType.A: "ACK Scan",
            ScanType.F: "FIN Scan",
            ScanType.X: "Xmas Scan",
            ScanType.N: "Null Scan",
            ScanType.M: "Maimon's Scan",
            ScanType.W: "Window Scan"
        }

        return scan_type_switcher[scan_type]

    @staticmethod
    def _convert_port_results(port_results: []):
        return [PortResultViewModel(port_result) for port_result in port_results]

    def get_positive_port_results(self):
        return [port_result for port_result in self.port_result_vms if port_result.error_wm is ScannerError.NoError]