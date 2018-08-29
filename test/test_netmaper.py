import unittest
import socket
from netmaper import Netmaper


class TestNetmaper(unittest.TestCase):

    def test_invalid_ip(self):
        scanner = Netmaper()
        result = scanner.map_network(scan_type="A", network_ip="azd25-sz")
        self.assertIn("The given IP is not in the correct format", result)

    def test_valid_ip(self):
        scanner = Netmaper()
        result = scanner.map_network(scan_type="A", network_ip="192.168.0.1")
        self.assertNotIn("The given IP is not in the correct format", str(result))

    def test_wrong_scan(self):
        scanner = Netmaper()
        result = scanner.map_network(scan_type="zxdsz", network_ip="192.168.0.1")
        self.assertIn("Wrong scan type specified", result)

    def test_arp_scan_correct_response(self):
        scanner = Netmaper()
        result = scanner.map_network(scan_type="A", network_ip="127.0.0.1")
        self.assertIsNotNone(result)

    def test_arp_scan_no_response(self):
        scanner = Netmaper()
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        result = scanner.map_network(scan_type="A", network_ip="127.0.0.1")
        s.recv(1024)
        self.assertFalse(result)

