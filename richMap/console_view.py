from richMap.host_discovery.model.host_discovery_types import HostDiscoveryTypes
from richMap.port_scanning.model.scan_types import ScanTypes


class ConsoleView:
    def __init__(self, controller):
        self.controller = controller
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

        scan_type_enum = ScanTypes[self.controller.arguments.scan_type]
        scan_type_str = self.scan_types[scan_type_enum]
        target = self.controller.arguments.target

        info = "Performing {0} on {1}".format(scan_type_str, target)

        if not results:
            print("No ports returned as open")
            return

        self._print_output(results, info)

    def print_net_map_results(self, results):
        """Prints out the results of network mapping"""

        map_type_enum = HostDiscoveryTypes[self.controller.arguments.map]
        map_type = self.map_types[map_type_enum]
        target = self.controller.arguments.target
        interface = self.controller.arguments.net_int

        info = "Performing {0} on {1} ({2})".format(
            map_type, target, interface)

        if not results:
            print("No hosts returned as online")
            return

        self._print_output(results, info)

    @staticmethod
    def print_error(failure_message):
        print("Error: " + failure_message)

    def _print_output(self, results, info):
        print(info)
        print("--" * 12)

        if self.controller.arguments.verbosity == 2:
            for item in results:
                print(item)
        else:
            for item in results:
                if "Open" in item or "Filtered" in item or "Unfiltered" in item or "Host Up" in item:
                    print(item)
