from port_scanning.model.port_result import PortResult, PortState
from port_scanning.scans.abstract_port_scan import AbstractPortScan
from scapy.all import IP, TCP


class NullPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortResult:
        packet = IP(target) / TCP(dport=[80, port], flags="")
        result = super().send_probe_packet(packet, target, port, timeout)

        if result is PortState.NoResponse:
            return PortResult(port, PortState.Open, True)

        if result[TCP].flags.R:
            return PortResult(port, PortState.Closed, False)

        return PortResult(port, result, False)
