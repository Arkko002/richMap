from host_discovery.scans.arp_discovery import ArpDiscovery
from host_discovery.scans.icmp_discovery import IcmpDiscovery
from host_discovery.scans.ping_discovery import PingDiscovery
from host_discovery.scans.syn_discovery import SynDiscovery
from factories.abstract_scanner_factory import AbstractScannerFactory
from factories.socket_type import SocketType
from scanner_socket.scanner_socket import ScannerSocket


class HostDiscoveryScanFactory(AbstractScannerFactory):
    def get_scanner(self, scanner_type):
        host_discovery = {
            "P": PingDiscovery,
            "A": ArpDiscovery,
            "I": IcmpDiscovery,
            "S": SynDiscovery
        }

        # TODO Proper error handling
        if scanner_type not in host_discovery:
            return "Wrong scan type specified"

        if scanner_type == "I":
            soc = ScannerSocket(SocketType.ICMP)
        elif scanner_type == "P":
            soc = ScannerSocket(SocketType.TCP)
        else:
            soc = ScannerSocket(SocketType.TCPRaw)

        return host_discovery[scanner_type](soc)
