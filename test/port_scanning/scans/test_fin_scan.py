import unittest
from unittest.mock import MagicMock

from richMap.factories.socket_type import SocketType
from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.model.tcp_flags import TcpFlags
from richMap.port_scanning.model.tcp_response_packet import TcpResponsePacket
from richMap.port_scanning.scans.fin_scan import FinPortScan
from richMap.scanner_socket import ScannerSocket


class TestFinPortScan(unittest.TestCase):
    def setUp(self):
        self.scanner_socket = ScannerSocket(SocketType.TCPRaw)
        self.fin_scan = FinPortScan(self.scanner_socket)

    def get_scan_result_when_filtered(self):
        self.scanner_socket.send_packet_and_return_result = MagicMock(return_value=PortState.Filtered)

        result = self.fin_scan.get_scan_result("test_target", 80, 3.0)

        self.assertEqual(result, PortState.Filtered)

    def get_scan_result_when_closed(self):
        test_packet = TcpResponsePacket([TcpFlags.RST], "test_header")
        self.scanner_socket.send_packet_and_return_result = MagicMock(return_value=test_packet)

        result = self.fin_scan.get_scan_result("test_target", 80, 3.0)

        self.assertEqual(result, PortState.Closed)

