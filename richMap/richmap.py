import argparse
import portscanner
import netmaper
import sys

def parse_args(argv=sys.argv[1:]):
    """Parses the command line arguments"""

    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", type=str, action="store",
                        dest="range", metavar="RNG", help="Port range separated with '-'.")
    parser.add_argument("-t", "--target", type=str, action="store",
                        dest="target", metavar="HST", help="IP of the target machine.")
    parser.add_argument("-s", "--scan", type=str, action="store",
                        dest="scan_type", metavar="SCN", help="The type of port scan to be used.")
    parser.add_argument("-m", "--map", action="store",
                        dest="map", help="The type of network scan to be used")
    parser.add_argument("-i", "--interface", help="Interface to be checked with ARP scan",
                        dest="net_int", action="store")
    return parser.parse_args(argv)


if __name__ == "__main__":
    Arguments = parse_args()
    Scan = portscanner.PortScanner()
    Map = netmaper.Netmaper()

    if Arguments.scan_type is not None:
        print(Scan.perform_scan(target=Arguments.target, port_range=Arguments.range,
                                scan_type=Arguments.scan_type))

    if Arguments.map is not None:
        print(Map.map_network(network_ip=Arguments.target, scan_type=Arguments.map,
                              net_interface=Arguments.net_int))

