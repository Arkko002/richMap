import re
from richMap.port_scanning.result_factories.abstract_host_result_factory import AbstractHostResultFactory
from richMap.port_scanning.result_factories.abstract_port_result_factory import AbstractPortResultFactory


class PortScanner(object):
    def __init__(self,
                 target,
                 scan,
                 port_range,
                 host_result_factory: AbstractHostResultFactory,
                 port_result_factory: AbstractPortResultFactory):
        if self._check_if_valid_address(target) is False:
            # TODO Error handling
            pass

        self.target = target
        self.scan = scan

        self.port_range = [int(port) for port in port_range]
        # Currently scanned port
        self.current_port = port_range[0]

        self.host_result = host_result_factory.get_host_result(target, scan.scan_type)
        self.port_result_factory = port_result_factory

    def perform_scan(self):
        """Performs a scans on target with parameters provided on object initialisation.
        Returns HostResult object."""
        port_states = (state for state in self._port_state_generator(self.target, self.port_range, 3.0))
        port_results = (self._port_result_generator(self.current_port, port_state) for port_state in port_states)
        self.host_result.port_result_vms = port_results

        return self.host_result

    @staticmethod
    def _check_if_valid_address(target):
        # TODO IPv6 support
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if not r.match(target):
            return False

        return True

    def _port_state_generator(self, target, port_range, timeout):
        for port in range(port_range[0], port_range[1]):
            self.current_port = port
            yield self.scan.get_scan_result(target, port, timeout)

    def _port_result_generator(self, port, port_state):
        yield self.port_result_factory.get_port_result(port, port_state)
