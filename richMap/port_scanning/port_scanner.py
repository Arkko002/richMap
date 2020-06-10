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
        self.target = target
        self.scan = scan
        self.port_range = port_range.split("-")

        self.host_result = host_result_factory.get_host_result(target, scan.scan_type)
        self.port_result_factory = port_result_factory

    def perform_scan(self):
        """Performs a scans on target with parameters provided on object initialisation.
        Returns HostResult object."""
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if r.match(self.target) is False:
            return "The given IP is not in the correct format"

        for port in range(int(self.port_range[0]), int(self.port_range[1]) + 1):
            # TODO timeout in scans switcher
            port_state = self.scan.get_scan_result(self.target, port, 3.0)
            port_result = self.port_result_factory.get_port_result(port, port_state)

            self.host_result.port_results.append(port_result)

        return self.host_result
