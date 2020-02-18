from richMap.host_discovery.mapping_types import MappingTypes
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
            MappingTypes.P: PingDiscovery,
            MappingTypes.A: ArpDiscovery,
            MappingTypes.I: IcmpDiscovery,
            MappingTypes.S: SynDiscovery
        }

        if scanner_type not in host_discovery:
            return "Wrong scan type specified"

        socket_swticher = {
            MappingTypes.I: SocketType.ICMP,
            MappingTypes.A: SocketType.TCPRaw,
            MappingTypes.P: SocketType.TCP,
            MappingTypes.S: SocketType.TCPRaw
        }

        soc = ScannerSocket(socket_swticher[scanner_type])
        return host_discovery[scanner_type](soc)
