from richMap.host_discovery.model.network_discovery_result import NetworkDiscoveryResult
from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from richMap.host_discovery.scans.arp_discovery import ArpDiscovery
from richMap.host_discovery.scans.syn_discovery import SynDiscovery
from richMap.host_discovery.viewmodel.host_discovery_vm import HostDiscoveryViewModel


class NetworkDiscoveryViewModel:
    def __init__(self, network_discovery_result: NetworkDiscoveryResult):
        self.network_ip_str = "Network IP: " + network_discovery_result.network_ip
        self.host_discovery_type_str = self._convert_host_discovery_to_str(network_discovery_result.host_discovery)

        self.results_vms = self._convert_host_discovery_results_to_vms(network_discovery_result.host_results)

    def __str__(self):
        return f"Results of {self.host_discovery_type_str} on {self.network_ip_str}"

    @staticmethod
    def _convert_host_discovery_to_str(host_discovery_type: AbstractHostDiscovery):

        host_discovery_type_switcher = {
            ArpDiscovery: "ARP Discovery",
            SynDiscovery: "SYN Discovery"
        }
        return host_discovery_type_switcher[host_discovery_type]

    @staticmethod
    def _convert_host_discovery_results_to_vms(host_discovery_results):
        return [HostDiscoveryViewModel(host_discovery_result) for host_discovery_result in host_discovery_results]
