from richMap.port_scanning.model.port_result import PortState
from richMap.port_scanning.model.tcp_response_packet import TcpFlags
from richMap.port_scanning.scans.abstract_port_scan import AbstractPortScan
from richMap.util.packet_generator import PacketGenerator


class MaimonPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortState:
        packet = PacketGenerator.generate_tcp_header(port, fin=1, ack=1)
        result = super().send_probe_packet_and_get_result(packet, target, port, timeout)

        if result is PortState.NoResponse:
            return PortState.Open

        if TcpFlags.RST in result.tcp_flags:
            return PortState.Closed

        if result is PortState and result is not PortState.NoResponse:
            return result
