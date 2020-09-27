import os

from host_discovery.viewmodel.network_discovery_vm import NetworkDiscoveryViewModel
from port_scanning.viewmodel.host_result_vm import HostResultViewModel
from util.ansi_sequences import ansi_sequences

# TODO Verbosity, check for verbosity on each print then act accordingly, all info and debug messages sent from model to view
class ConsoleView:
    def __init__(self, controller, verbosity):
        self.controller = controller
        self.verbosity = verbosity

    def print_results(self, result_object_vm: HostResultViewModel):
        """Prints out the results of port scan"""
        print(str(result_object_vm))
        self._print_separator()

        # TODO high and low verbosity
        for result in result_object_vm.result_vms:
            print(str(result))

    @staticmethod
    def print_error(failure_message):
        print(f"{ansi_sequences['error']} {failure_message} {ansi_sequences['end_sequence']}")

    @staticmethod
    def _print_separator():
        # TODO better solution
        """ Print separator using the character column width """
        rows, columns = os.popen("stty size", "r").read().split()
        print("-" * int(columns))
