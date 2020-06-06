from richMap.port_scanning.model.scan_types import ScanTypes
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
from richMap.scan_factories.socket_type import SocketType
from richMap.scanner_socket import ScannerSocket


class PortScanFactory(AbstractScannerFactory):
    def get_scanner(self, scanner_type):
        scans = {
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

        if scanner_type not in scans:
            return "Wrong scan type specified"

        scan_enum = ScanTypes(scanner_type)

        if scan_enum == ScanTypes.T:
            soc = ScannerSocket(SocketType.TCP)
        elif scan_enum == ScanTypes.U:
            soc = ScannerSocket(SocketType.UDP)
        else:
            soc = ScannerSocket(SocketType.TCPRaw)

        return scans[scanner_type](soc)

