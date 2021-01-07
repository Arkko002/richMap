import os

from util.ansi_sequences import ansi_sequences


class ConsoleView:
    def __init__(self, verbosity):
        self.verbosity = verbosity

    def print_results(self, result_object_vm):
        """Prints out the results of port scan"""
        print(str(result_object_vm))
        self._print_separator()

        if self.verbosity == 0:
            for result in result_object_vm.result_vms:
                if result.result_positive:
                    print(str(result))
        elif self.verbosity >= 1:
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
