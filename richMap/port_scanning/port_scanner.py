import socket

from richMap.port_scanning.scans.ack_scan import AckScan
from richMap.port_scanning.scans.fin_scan import FinScan
from richMap.port_scanning.scans.maimon_scan import MaimonScan
from richMap.port_scanning.scans.null_scan import NullScan
from richMap.port_scanning.scans.syn_sca import SynScan
from richMap.port_scanning.host_result import HostResult
from richMap.port_scanning.port_scanner_socket import PortScannerSocket
from richMap.port_scanning.response_packet import TcpFlags
from richMap.port_scanning.scans.tcp_scan import TcpScan
from richMap.port_scanning.scans.udp_scan import UdpScan
from richMap.port_scanning.scans.window_scan import WindowScan
from richMap.port_scanning.scans.xmas_scan import XmasScan
from richMap.port_scanning.socket_type import SocketType
from richMap.util.packet_generator import PacketGenerator
from richMap.port_scanning.scan_types import ScanTypes
from richMap.port_scanning.port_result import PortState, PortResult
import re


class PortScanner(object):
    def __init__(self, target: str, scan_type: ScanTypes, port_range):
        self.target = target
        self.scan_type = scan_type
        self.port_range = port_range.split("-")

        if scan_type == ScanTypes.T:
            self.soc = PortScannerSocket(SocketType.TCP)
        elif scan_type == ScanTypes.U:
            self.soc = PortScannerSocket(SocketType.UDP)
        else:
            self.soc = PortScannerSocket(SocketType.TCPRaw)

    def __del__(self):
        self.soc.close_sockets()

    def perform_scan(self):
        """Base function to be called when performing scan"""

        scans = {
            ScanTypes.T: TcpScan,
            ScanTypes.S: SynScan,
            ScanTypes.U: UdpScan,
            ScanTypes.A: AckScan,
            ScanTypes.F: FinScan,
            ScanTypes.X: XmasScan,
            ScanTypes.N: NullScan,
            ScanTypes.M: MaimonScan,
            ScanTypes.W: WindowScan
        }

        if self.scan_type not in scans:
            return "Wrong scan type specified"

        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if r.match(self.target) is False:
            return "The given IP is not in the correct format"

        host_result = HostResult(self.target, self.scan_type)
        scan = scans[self.scan_type]

        for port in range(int(self.port_range[0]), int(self.port_range[1]) + 1):
            # TODO timeout in scans switcher
            port_state = scan.get_scan_result(self.target, port, 3.0)
            port_result = PortResult(port, port_state)

            host_result.port_results.append(port_result)

        return host_result

    # TODO
    def _ip_protocol_scan(self, target: str, soc: socket, soc_icmp: socket):
        return



