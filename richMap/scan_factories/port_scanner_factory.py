from richMap.port_scanning.scan_types import ScanTypes
from richMap.port_scanning.scans.ack_scan import AckPortScan
from richMap.port_scanning.scans.fin_scan import FinPortScan
from richMap.port_scanning.scans.maimon_scan import MaimonPortScan
from richMap.port_scanning.scans.null_scan import NullPortScan
from richMap.port_scanning.scans.syn_sca import SynPortScan
from richMap.port_scanning.scans.tcp_scan import TcpPortScan
from richMap.port_scanning.scans.udp_scan import UdpPortScan
from richMap.port_scanning.scans.window_scan import WindowPortScan
from richMap.port_scanning.scans.xmas_scan import XmasPortScan
from richMap.scan_factories.abstract_scanner_factory import AbstractScannerFactory


class PortScannerFactory(AbstractScannerFactory):
    def __init__(self):
        self.scans = {
            ScanTypes.T: TcpPortScan,
            ScanTypes.S: SynPortScan,
            ScanTypes.U: UdpPortScan,
            ScanTypes.A: AckPortScan,
            ScanTypes.F: FinPortScan,
            ScanTypes.X: XmasPortScan,
            ScanTypes.N: NullPortScan,
            ScanTypes.M: MaimonPortScan,
            ScanTypes.W: WindowPortScan
        }

    def get_scanner(self, scanner_type, soc):
        return self.scans[scanner_type](soc)

