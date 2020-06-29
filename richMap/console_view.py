import os

from richMap.host_discovery.viewmodel.network_discovery_vm import NetworkDiscoveryViewModel
from richMap.port_scanning.viewmodel.host_result_vm import HostResultViewModel
from richMap.util.ansi_sequences import ansi_sequences


class ConsoleView:
    def __init__(self, controller):
        self.controller = controller

    def print_port_scan_results(self, host_result_vm: HostResultViewModel):
        """Prints out the results of port scan"""
        str(host_result_vm)
        self._print_separator()

        # TODO high and low verbosity
        for port_result in host_result_vm.port_result_vms:
            print(str(port_result))

    def print_host_discovery_results(self, network_result_vm: NetworkDiscoveryViewModel):
        """Prints out the results of network mapping"""
        print(str(network_result_vm))
        self._print_separator()

        # TODO high and low verbosity
        for host_result in network_result_vm.host_discovery_results_vms:
            print(str(host_result))

    @staticmethod
    def print_error(failure_message):
        print(f"{ansi_sequences['error']} {failure_message} {ansi_sequences['end_sequence']}")

    @staticmethod
    def _print_separator():
        """ Print separator using the character column width """
        rows, columns = os.popen("stty size", "r").read().split()
        print("-" * columns)
