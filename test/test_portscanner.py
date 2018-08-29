import unittest
from portscanner import PortScanner


class TestPortScanner(unittest.TestCase):

    def test_invalid_ip(self):
        scanner = PortScanner()
        result = scanner.perform_scan(scan_type="T", target="azd25-sz", port_range="60-200")
        self.assertIn(result, "The given IP is not in the correct format")

    def test_valid_ip(self):
        scanner = PortScanner()
        result = scanner.perform_scan(scan_type="T", target="127.0.0.1", port_range="60-200")
        self.assertNotIn(str(result), "The given IP is not in the correct format")

    def test_wrong_scan(self):
        scanner = PortScanner()
        result = scanner.perform_scan(scan_type="zxdsz", target="127.0.0.1", port_range="60-200")
        self.assertIn(result, "Wrong scan type specified")


