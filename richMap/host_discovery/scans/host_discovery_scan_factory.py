from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from host_discovery.scans.arp_discovery import ArpDiscovery
from host_discovery.scans.ping_discovery import PingDiscovery
from host_discovery.scans.syn_discovery import SynDiscovery
from abstract_scanner_factory import AbstractScannerFactory
from scanner_socket.socket_type import SocketType
from scanner_socket.scanner_socket import ScannerSocket


class HostDiscoveryScanFactory(AbstractScannerFactory):
    """Translates the CLI commands into objects that inherit from AbstractHostDiscovery"""
    def get_scanner(self, scanner_type: str) -> AbstractHostDiscovery:
        """
        Returns a host discoverer object that corresponds to provided CLI option

        :param scanner_type: String representing the type of discoverer
        :return: Discoverer that inherits from AbstractHostDiscovery
        """
        host_discovery = {
            "P": PingDiscovery,
            "A": ArpDiscovery,
            "S": SynDiscovery
        }

        if scanner_type not in host_discovery:
            raise KeyError

        if scanner_type == "I":
            soc = ScannerSocket(SocketType.ICMP)
        elif scanner_type == "P":
            soc = ScannerSocket(SocketType.TCP)
        else:
            soc = ScannerSocket(SocketType.TCPRaw)

        return host_discovery[scanner_type](soc)
