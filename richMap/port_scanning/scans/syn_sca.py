from richMap.port_scanning.port_result import PortState
from richMap.port_scanning.response_packet import TcpFlags
from richMap.port_scanning.scans.abstract_port_scan import AbstractPortScan
from richMap.util.packet_generator import PacketGenerator


class SynPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortState:
        packet = PacketGenerator.generate_tcp_header(port, syn=1)
        result = super().send_probe_packet_and_get_result(packet, target, port, timeout)

        if result is PortState:
            return result

        if TcpFlags.SYN in result.tcp_flags and TcpFlags.ACK in result.tcp_flags and len(result.tcp_flags) == 2:
            return PortState.Open
        elif TcpFlags.SYN in result.tcp_flags and len(result.tcp_flags) == 1:
            return PortState.Open
        elif TcpFlags.RST in result.tcp_flags and len(result.tcp_flags) == 1:
            return PortState.Closed
