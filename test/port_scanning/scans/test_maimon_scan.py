import unittest
from unittest.mock import MagicMock

from richMap.factories.socket_type import SocketType
from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.model.tcp_flags import TcpFlags
from richMap.port_scanning.model.tcp_response_packet import TcpResponsePacket
from richMap.port_scanning.scans.maimon_scan import MaimonPortScan
from richMap.scanner_socket import ScannerSocket


class TestFinPortScan(unittest.TestCase):
    def setUp(self):
        self.scanner_socket = ScannerSocket(SocketType.TCPRaw)
        self.maimon_scan = MaimonPortScan(self.scanner_socket)

    def get_scan_result_when_filtered(self):
        self.scanner_socket.send_packet_and_return_result = MagicMock(return_value=PortState.Filtered)

        result = self.maimon_scan.get_scan_result("test_target", 80, 3.0)

        self.assertEqual(result, PortState.Filtered)

    def get_scan_result_when_closed(self):
        test_packet = TcpResponsePacket([TcpFlags.RST], "test_header")
        self.scanner_socket.send_packet_and_return_result = MagicMock(return_value=test_packet)

        result = self.maimon_scan.get_scan_result("test_target", 80, 3.0)

        self.assertEqual(result, PortState.Closed)
