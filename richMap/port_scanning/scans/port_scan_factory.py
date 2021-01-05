from port_scanning.scans.abstract_port_scan import AbstractPortScan
from port_scanning.scans.ack_scan import AckPortScan
from port_scanning.scans.fin_scan import FinPortScan
from port_scanning.scans.maimon_scan import MaimonPortScan
from port_scanning.scans.null_scan import NullPortScan
from port_scanning.scans.tcp_scan import TcpPortScan
from port_scanning.scans.window_scan import WindowPortScan
from port_scanning.scans.xmas_scan import XmasPortScan
from abstract_scanner_factory import AbstractScannerFactory
from scanner_socket.socket_type import SocketType
from scanner_socket.threaded_scanner_socket import ThreadedScannerSocket

class PortScanFactory(AbstractScannerFactory):
    """Translates the CLI commands into objects that inherit from AbstractPortScan"""
    def get_scanner(self, scanner_type: str) -> AbstractPortScan:
        """
        Returns a port scanner object that corresponds to provided CLI option

        :param scanner_type: String representing the type of the scanner
        :return: Scanner that inherits from AbstractPortScan
        """
        scans = {
            "T": TcpPortScan,
            "A": AckPortScan,
            "F": FinPortScan,
            "X": XmasPortScan,
            "N": NullPortScan,
            "M": MaimonPortScan,
            "W": WindowPortScan
        }

        if scanner_type == "T":
            soc = ThreadedScannerSocket(SocketType.TCP, 3.0)
        else:
            soc = ThreadedScannerSocket(SocketType.TCPRaw, 3.0)

        return scans[scanner_type](soc)

