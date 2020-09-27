from port_scanning.model.port_result import PortResult, PortState
from port_scanning.scans.abstract_port_scan import AbstractPortScan


class TcpPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortResult:
        if self.soc.try_connecting_to_port(target, port):
            return PortResult(port, PortState.Open, True)
        else:
            return PortResult(port, PortState.Closed, False)
