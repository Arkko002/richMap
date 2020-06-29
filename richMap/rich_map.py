import argparse
import sys

from richMap.host_discovery.host_discoverer import HostDiscoverer
from richMap.host_discovery.model.host_discovery_types import HostDiscoveryType
from richMap.host_discovery.model.network_discovery_result import NetworkDiscoveryResult
from richMap.port_scanning.model.scan_types import ScanType
from richMap.scan_factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from richMap.scan_factories.port_scan_factory import PortScanFactory
from richMap.port_scanning.result_factories.host_result_factory import HostResultFactory
from richMap.port_scanning.result_factories.port_result_factory import PortResultFactory
from .port_scanning.port_scanner import PortScanner
from .console_view import ConsoleView


# TODO Add viewmodels
class RichMap(object):

    def __init__(self):
        self.arguments = self._parse_args()
        self.view = ConsoleView(self)

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
            self.view.print_port_scan_results(result)

        elif self.arguments.map_type is not None:
            result = self._get_host_discovery_results()
            self.view.print_host_discovery_results(result)

        if self.arguments.scan_type is None and self.arguments.map_type is None:
            self.view.print_error("No scan specified")

    def _get_port_scan_results(self):
        scanner_factory = PortScanFactory()
        scan_type = ScanTypes(self.arguments.scan_type)

        scan = scanner_factory.get_scanner(scan_type)
        if scan is str:
            self.view.print_error(scan)

        host_result_factory = HostResultFactory()
        port_result_factory = PortResultFactory()

        scanner = PortScanner(self.arguments.target,
                              scan,
                              self.arguments.range,
                              host_result_factory,
                              port_result_factory)

        return scanner.perform_scan()

    def _get_host_discovery_results(self):
        host_discovery_factory = HostDiscoveryScanFactory()
        host_discovery_type = HostDiscoveryTypes(self.arguments.map_type)

        scan = host_discovery_factory.get_scanner(host_discovery_type)
        if scan is str:
            self.view.print_error(scan)

        network_result = NetworkDiscoveryResult(self.arguments.target, host_discovery_type)

        mapper = HostDiscoverer(self.arguments.target, network_result, scan)
        return mapper.map_network()


if __name__ == "__main__":
    controller = RichMap()
    controller.get_scan_results()
