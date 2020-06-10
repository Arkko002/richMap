import argparse
import sys

from richMap.host_discovery.host_discovery_types import HostDiscoveryTypes
from richMap.host_discovery.network_discovery_result import NetworkDiscoveryResult
from richMap.port_scanning.model.scan_types import ScanTypes
from richMap.factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from richMap.factories.port_scan_factory import PortScanFactory
from richMap.port_scanning.result_factories.host_result_factory import HostResultFactory
from richMap.port_scanning.result_factories.port_result_factory import PortResultFactory
from .host_discovery.net_mapper import Netmapper
from .port_scanning.port_scanner import PortScanner


# TODO Add viewmodels
class CLIController(object):

    def __init__(self):
        self.arguments = self.__parse_args()
        self.view = CLIView(self)

    @staticmethod
    def __parse_args(argv=sys.argv[1:]):
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

            result = scanner.perform_scan()

            self.view.print_port_scan_results(result)

        elif self.arguments.map_type is not None:
            host_discovery_factory = HostDiscoveryScanFactory()
            host_discovery_type = HostDiscoveryTypes(self.arguments.map_type)

            scan = host_discovery_factory.get_scanner(host_discovery_type)
            if scan is str:
                self.view.print_error(scan)

            network_result = NetworkDiscoveryResult(self.arguments.target, host_discovery_type)

            mapper = Netmapper(self.arguments.target, network_result, scan)
            result = mapper.map_network()

            self.view.print_net_map_results(result)

        if self.arguments.scan_type is None and self.arguments.map_type is None:
            self.view.print_error("No scan specified")


class CLIView:
    def __init__(self, parent):
        self.parent = parent
        self.scan_types = {
            ScanTypes.T: "TCP Scan",
            ScanTypes.S: "SYN Scan",
            ScanTypes.U: "UDP Scan",
            ScanTypes.A: "ACK Scan",
            ScanTypes.F: "FIN Scan",
            ScanTypes.X: "Xmas Scan",
            ScanTypes.N: "Null Scan",
            ScanTypes.M: "Maimon's Scan",
            ScanTypes.W: "Window Scan"
        }

        self.map_types = {
            HostDiscoveryTypes.P: "Ping Scan",
            HostDiscoveryTypes.A: "ARP Scan",
            HostDiscoveryTypes.F: "FIN Scan",
            HostDiscoveryTypes.S: "SYN Scan",
            HostDiscoveryTypes.N: "Null Scan",
            HostDiscoveryTypes.I: "ICMP Scan",
            HostDiscoveryTypes.X: "Xmas Scan"
        }

    def print_port_scan_results(self, results):
        """Prints out the results of port scan"""

        scan_type_enum = ScanTypes[self.parent.arguments.scan_type]
        scan_type = self.scan_types[scan_type_enum]
        target = self.parent.arguments.target
        info = "Performing {0} on {1}".format(scan_type, target)

        if not results:
            print("No ports returned as open")
            return

        self.__print_output(results, info)

    def print_net_map_results(self, results):
        """Prints out the results of network mapping"""

        map_type_enum = HostDiscoveryTypes[self.parent.arguments.map]
        map_type = self.map_types[map_type_enum]
        target = self.parent.arguments.target
        interface = self.parent.arguments.net_int
        info = "Performing {0} on {1} ({2})".format(
            map_type, target, interface)

        if not results:
            print("No hosts returned as online")
            return

        self.__print_output(results, info)

    @staticmethod
    def print_error(failure_message):
        print("Error: " + failure_message)

    def __print_output(self, results, info):
        print(info)
        print("--" * 12)

        if self.parent.arguments.verbosity == 2:
            for item in results:
                print(item)
        else:
            for item in results:
                if "Open" in item or "Filtered" in item or "Unfiltered" in item or "Host Up" in item:
                    print(item)


if __name__ == "__main__":
    controller = CLIController()
    controller.get_scan_results()
