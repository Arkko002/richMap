from richMap.port_scanning.port_result import PortState
from richMap.port_scanning.scans.abstract_scan import AbstractScan


class TcpScan(AbstractScan):
    def get_scan_result(self, target, port, timeout):
        if self.soc.try_connecting_to_port(target, port):
            return PortState.Open
        else:
            return PortState.Closed
