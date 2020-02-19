from richMap.host_discovery.host_discovery_types import HostDiscoveryTypes
from richMap.host_discovery.scans.arp_discovery import ArpDiscovery
from richMap.host_discovery.scans.icmp_discovery import IcmpDiscovery
from richMap.host_discovery.scans.ping_discovery import PingDiscovery
from richMap.host_discovery.scans.syn_discovery import SynDiscovery
from richMap.scan_factories.abstract_scanner_factory import AbstractScannerFactory
from richMap.scan_factories.socket_type import SocketType
from richMap.scanner_socket import ScannerSocket


class HostDiscoveryScanFactory(AbstractScannerFactory):
    def get_scanner(self, scanner_type):
        host_discovery = {
            HostDiscoveryTypes.P: PingDiscovery,
            HostDiscoveryTypes.A: ArpDiscovery,
            HostDiscoveryTypes.I: IcmpDiscovery,
            HostDiscoveryTypes.S: SynDiscovery
        }

        if scanner_type not in host_discovery:
            return "Wrong scan type specified"

        socket_swticher = {
            HostDiscoveryTypes.I: SocketType.ICMP,
            HostDiscoveryTypes.A: SocketType.TCPRaw,
            HostDiscoveryTypes.P: SocketType.TCP,
            HostDiscoveryTypes.S: SocketType.TCPRaw
        }

        soc = ScannerSocket(socket_swticher[scanner_type])
        return host_discovery[scanner_type](soc)
