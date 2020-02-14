import argparse

from richMap.host_discovery.mapping_types import MappingTypes
from richMap.host_discovery.scans.arp_discovery import ArpDiscovery
from richMap.host_discovery.scans.ping_discovery import PingDiscovery
from richMap.port_scanning.scans.ack_scan import AckPortScan
from richMap.port_scanning.scans.fin_scan import FinPortScan
from richMap.port_scanning.scans.maimon_scan import MaimonPortScan
from richMap.port_scanning.scans.null_scan import NullPortScan
from richMap.port_scanning.scans.syn_sca import SynPortScan
from richMap.port_scanning.scans.tcp_scan import TcpPortScan
from richMap.port_scanning.scans.udp_scan import UdpPortScan
from richMap.port_scanning.scans.window_scan import WindowPortScan
from richMap.port_scanning.scans.xmas_scan import XmasPortScan
from richMap.port_scanning.socket_type import SocketType
from richMap.scanner_socket import ScannerSocket
from .port_scanning.port_scanner import PortScanner
from .host_discovery.net_mapper import Netmapper
from richMap.host_discovery.map_types import MapTypes
from richMap.port_scanning.scan_types import ScanTypes
import sys

class CLIController(object):

    def __init__(self):
        self.arguments = self.__parse_args()
        self.view = CLIView(self)

        self.scans = {
            ScanTypes.T: TcpPortScan,
            ScanTypes.S: SynPortScan,
            ScanTypes.U: UdpPortScan,
            ScanTypes.A: AckPortScan,
            ScanTypes.F: FinPortScan,
            ScanTypes.X: XmasPortScan,
            ScanTypes.N: NullPortScan,
            ScanTypes.M: MaimonPortScan,
            ScanTypes.W: WindowPortScan
        }

        self.host_discovery = {
            MappingTypes.PingScan: PingDiscovery,
            MappingTypes.ArpScan: ArpDiscovery,
        }

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
            if self.arguments.scan_type not in self.scans:
                return "Wrong scan type specified"

            if self.arguments.scan_type == ScanTypes.T:
                soc = ScannerSocket(SocketType.TCP)
            elif self.arguments.scan_type == ScanTypes.U:
                soc = ScannerSocket(SocketType.UDP)
            else:
                soc = ScannerSocket(SocketType.TCPRaw)

            scan = self.scans[self.arguments.scan_type](soc)
            scan_type = ScanTypes(self.arguments.scan_type)
            scanner = PortScanner(self.arguments.target, scan_type,
                                  scan=scan, port_range=self.arguments.range)
            result = scanner.perform_scan()

            self.view.print_port_scan_results(result)

        elif self.arguments.map_type is not None:
            if self.arguments.map_type not in self.host_discovery:
                return "Wrong scan type specified"

            if self.arguments.host_discovery_type.IcmpScan:
                soc = ScannerSocket(SocketType.ICMP)
            elif self.arguments.host_discovery_type.PingScan:
                soc = ScannerSocket(SocketType.TCP)
            else:
                soc = SocketType(SocketType.TCPRaw)

            host_discovery = self.host_discovery[self.arguments.map_type](soc)
            host_discovery_type = MappingTypes(self.arguments.map_type)
            mapper = Netmapper(network_ip=self.arguments.target, host_discovery_type=host_discovery_type,
                               host_discovery=host_discovery, net_interface=self.arguments.net_int)
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
            MapTypes.P: "Ping Scan",
            MapTypes.A: "ARP Scan",
            MapTypes.As: "ARP Stealth Scan",
            MapTypes.Ap: "ARP Passive Scan"
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

        map_type_enum = MapTypes[self.parent.arguments.map]
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
