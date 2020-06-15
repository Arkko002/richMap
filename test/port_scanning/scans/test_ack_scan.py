import unittest
from unittest.mock import MagicMock

from richMap.factories.socket_type import SocketType
from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.model.tcp_flags import TcpFlags
from richMap.port_scanning.model.tcp_response_packet import TcpResponsePacket
from richMap.port_scanning.scans.ack_scan import AckPortScan
from richMap.scanner_socket import ScannerSocket


class TestAckPortScan(unittest.TestCase):
    def setUp(self):
        self.scanner_socket = ScannerSocket(SocketType.TCPRaw)
        self.ack_scan = AckPortScan(self.scanner_socket)

    def get_scan_result_when_filtered(self):
        self.scanner_socket.send_packet_and_return_result = MagicMock(return_value=PortState.Filtered)

        result = self.ack_scan.get_scan_result("test_target", 80, 3.0)

        self.assertEqual(result, PortState.Filtered)

    def get_scan_result_when_unfiltered(self):
        test_packet = TcpResponsePacket([TcpFlags.RST], "test_header")
        self.scanner_socket.send_packet_and_return_result = MagicMock(return_value=test_packet)

        result = self.ack_scan.get_scan_result("test_target", 80, 3.0)

        self.assertEqual(result, PortState.Unfiltered)
