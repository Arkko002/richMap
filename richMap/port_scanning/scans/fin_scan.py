from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.model.port_result import PortResult
from richMap.port_scanning.scans.abstract_port_scan import AbstractPortScan
from scapy.layers.inet import IP, TCP


class FinPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortResult:
        packet = IP(target) / TCP(dport=[80, port], flags="F")
        result = super().send_probe_packet(packet, target, port)

        if isinstance(result, PortState):
            return PortResult(port, PortState.Open, True)

        if result[TCP].flags.R:
            return PortResult(port, PortState.Closed, False)

        return PortResult(port, result, False)
