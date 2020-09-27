import argparse
import sys

from host_discovery.host_discoverer import HostDiscoverer
from host_discovery.model.host_discovery_types import HostDiscoveryType
from host_discovery.model.network_discovery_result import NetworkDiscoveryResult
from factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from factories.port_scan_factory import PortScanFactory
from port_scanning.port_scanner import PortScanner
from console_view import ConsoleView
from port_scanning.viewmodel.host_result_vm import HostResultViewModel


class RichMap(object):

    def __init__(self):
        self.arguments = self._parse_args()
        self.view = ConsoleView(self, self.arguments.verbosity)

    @staticmethod
    def _parse_args(argv=sys.argv[1:]):
        """Parses the command line arguments"""

        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--range", type=str, action="store", default="1-1024", required=False,
                            dest="range", help="Port range separated with '-'.")

        parser.add_argument("-t", "--target", type=str, action="store", required=True,
                            dest="target", help="IP of the target machine / network.")

        parser.add_argument("-s", "--scan", type=str, action="store",
                            dest="scan_type", help="The type of port scan to be used.")

        parser.add_argument("-m", "--map", action="store",
                            dest="map_type", help="The type of network scan to be used")

        parser.add_argument("-i", "--interface", help="Interface to be checked with ARP scan",
                            dest="net_int", action="store")

        parser.add_argument("-v", "--verbosity", action="store", default=1,
                            dest="verbosity", type=int, help="Verbosity level (1-2)")

        return parser.parse_args(argv)

    def get_scan_results(self):
        """Sends the scan request to Model classes and delivers results to View class"""

        if self.arguments.scan_type is not None:
            result = self._get_port_scan_results()
            result_vm = HostResultViewModel(result)
            self.view.print_results(result_vm)

        elif self.arguments.map_type is not None:
            result = self._get_host_discovery_results()
            self.view.print_results(result)

        if self.arguments.scan_type is None and self.arguments.map_type is None:
            self.view.print_error("No scan specified")

    def _get_port_scan_results(self):
        scanner_factory = PortScanFactory()

        scan = scanner_factory.get_scanner(self.arguments.scan_type)
        if scan is str:
            self.view.print_error(scan)

        scanner = PortScanner(self.arguments.target, scan, self.arguments.range,)

        return scanner.perform_scan()

    def _get_host_discovery_results(self):
        host_discovery_factory = HostDiscoveryScanFactory()
        host_discovery_type = HostDiscoveryType(self.arguments.map_type)

        scan = host_discovery_factory.get_scanner(host_discovery_type)
        if scan is str:
            self.view.print_error(scan)

        network_result = NetworkDiscoveryResult(self.arguments.target, host_discovery_type)

        mapper = HostDiscoverer(self.arguments.target, network_result, scan)
        return mapper.map_network()


if __name__ == "__main__":
    controller = RichMap()
    controller.get_scan_results()
