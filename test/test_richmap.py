import unittest
import richmap
import sys
import io


class TestRichMap(unittest.TestCase):

    def test_no_scan_specified(self):
        controller = richmap.CLIController()
        old_stdout = sys.stdout
        sys.stdout = buffer = io.StringIO()
        controller.get_scan_results()
        sys.stdout = old_stdout
        output = buffer.getvalue()
        self.assertIn("No scan specified", output)

    def test_no_ports_open(self):
        return

    def test_ports_open(self):
        return

