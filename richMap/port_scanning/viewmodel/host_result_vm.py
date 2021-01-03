from port_scanning.model.host_result import HostResult
from port_scanning.scans.ack_scan import AckPortScan
from port_scanning.scans.fin_scan import FinPortScan
from port_scanning.scans.maimon_scan import MaimonPortScan
from port_scanning.scans.null_scan import NullPortScan
from port_scanning.scans.window_scan import WindowPortScan
from port_scanning.scans.xmas_scan import XmasPortScan
from port_scanning.viewmodel.port_result_wm import PortResultViewModel
# TODO from port_scanning.scans.syn_scan import SynPortScan
from port_scanning.scans.tcp_scan import TcpPortScan


class HostResultViewModel:
    """Converts HostResult data into formatting suitable for display"""
    def __init__(self, host_result: HostResult):
        """

        :param host_result: Source HostResult object
        """
        self.model_host_result = host_result

        self.target_str = "Target IP: " + host_result.target
        self.scan_type_str = self._convert_scan_type_to_str(host_result.scan)
        self.result_vms = self._convert_port_results(host_result.port_results)

    def __str__(self):
        return f"Results of {self.scan_type_str} on {self.target_str}"

    @staticmethod
    def _convert_scan_type_to_str(scan_type):
        scan_type_switcher = {
            TcpPortScan: "TCP Scan",
            #SynPortScan: "SYN Scan",
            AckPortScan: "ACK Scan",
            FinPortScan: "FIN Scan",
            XmasPortScan: "Xmas Scan",
            NullPortScan: "Null Scan",
            MaimonPortScan: "Maimon's Scan",
            WindowPortScan: "Window Scan"
        }

        return scan_type_switcher[type(scan_type)]

    @staticmethod
    def _convert_port_results(port_results: []):
        return [PortResultViewModel(port_result) for port_result in port_results]

    def get_positive_port_results(self):
        return [port_result for port_result in self.result_vms if port_result.result_positive is True]
