import argparse
import portscanner
import netmaper
import sys


class CLIController(object):

    def __init__(self):
        self.arguments = self.__parse_args()
        self.scan = portscanner.PortScanner()
        self.map = netmaper.Netmaper()
        self.view = CLIView(self)

    def __parse_args(self, argv=sys.argv[1:]):
        """Parses the command line arguments"""

        parser = argparse.ArgumentParser()
        parser.add_argument("-r", "--range", type=str, action="store",
                            dest="range", metavar="RNG", help="Port range separated with '-'.")
        parser.add_argument("-t", "--target", type=str, action="store",
                            dest="target", metavar="HST", help="IP of the target machine.")
        parser.add_argument("-s", "--scan", type=str, action="store",
                            dest="scan_type", metavar="SCN", help="The type of port scan to be used.")
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
            result = self.scan.perform_scan(target=self.arguments.target, port_range=self.arguments.range,
                                            scan_type=self.arguments.scan_type)
            self.view.print_port_scan_results(result)

        elif self.arguments.map_type is not None:
            result = self.map.map_network(network_ip=self.arguments.target, scan_type=self.arguments.map_type,
                                          net_interface=self.arguments.net_int)
            self.view.print_net_map_results(result)

        if self.arguments.scan_type is None and self.arguments.map_type is None:
            self.view.print_error("No scan specified")


class CLIView:
    def __init__(self, parent):
        self.parent = parent
        self.scan_types = {
            "T": "TCP Scan",
            "S": "SYN Scan",
            "U": "UDP Scan",
            "A": "ACK Scan",
            "F": "FIN Scan",
            "X": "Xmas Scan",
            "N": "Null Scan",
            "M": "Maimon's Scan",
            "W": "Window Scan"
        }

        self.map_types = {
            "P": "Ping Scan",
            "A": "ARP Scan",
            "As": "ARP Stealth Scan",
            "Ap": "ARP Passive Scan"
        }

    def print_port_scan_results(self, results):
        """Prints out the results of port scan"""

        scan_type = self.scan_types[self.parent.arguments.scan_type]
        target = self.parent.arguments.target
        info = "Performing {0} on {1}".format(scan_type, target)

        if not results:
            print("No ports returned as open")
            return

        self.__print_output(results, info)

    def print_net_map_results(self, results):
        """Prints out the results of network mapping"""

        map_type = self.map_types[self.parent.arguments.map]
        target = self.parent.arguments.target
        interface = self.parent.arguments.net_int
        info = "Performing {0} on {1} ({2})".format(map_type, target, interface)

        if not results:
            print("No hosts returned as online")
            return

        self.__print_output(results, info)

    @staticmethod
    def print_error(failure_message):
        print("Error: " + failure_message)

    def __print_output(self, results, info):
        print(info)
        print("--"*12)

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

