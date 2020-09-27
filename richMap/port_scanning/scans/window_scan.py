from port_scanning.model.port_result import PortResult, PortState
from port_scanning.scans.abstract_port_scan import AbstractPortScan
from scapy.layers.inet import IP, TCP


class WindowPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortResult:
        packet = IP(target) / TCP(dport=[80, port], flags="A")
        result = super().send_probe_packet(packet, target, port, 3.0)

        if result is PortState:
            return PortResult(port, result, False)

        if result[TCP].flags.R:
            if result[TCP].window > 0:
                return PortResult(port, PortState.Open, True)
            elif result[TCP].window == 0:
                return PortResult(port, PortState.Closed, False)
