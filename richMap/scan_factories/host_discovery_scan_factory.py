from richMap.host_discovery.mapping_types import MappingTypes
from richMap.host_discovery.scans.arp_discovery import ArpDiscovery
from richMap.host_discovery.scans.icmp_discovery import IcmpDiscovery
from richMap.host_discovery.scans.ping_discovery import PingDiscovery
from richMap.host_discovery.scans.syn_discovery import SynDiscovery
from richMap.scan_factories.abstract_scanner_factory import AbstractScannerFactory


class HostDiscoveryScanFactory(AbstractScannerFactory):
    def __init__(self):
        self.host_discovery = {
            MappingTypes.P: PingDiscovery,
            MappingTypes.A: ArpDiscovery,
            MappingTypes.I: IcmpDiscovery,
            MappingTypes.S: SynDiscovery
        }

    def get_scanner(self, scanner_type, soc):
        return self.host_discovery[scanner_type](soc)