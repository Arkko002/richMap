from port_scanning.model.port_result import PortResult, PortState
from port_scanning.scans.abstract_port_scan import AbstractPortScan
from scapy.layers.inet import IP, TCP


class AckPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortResult:
        packet = IP(dst=target) / TCP(dport=[80, port], flags="A")
        result = super().send_probe_packet(packet, target, port, timeout)

        if result is PortState:
            return PortResult(port, result, False)

        if result[TCP].flags.F:
            return PortResult(port, PortState.Unfiltered, True)
