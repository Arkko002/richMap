from richMap.port_scanning.model.port_result import PortState
from richMap.port_scanning.model.response_packet import TcpFlags
from richMap.port_scanning.scans.abstract_port_scan import AbstractPortScan
from richMap.util.packet_generator import PacketGenerator


class NullPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout) -> PortState:
        packet = PacketGenerator.generate_tcp_header(port)
        result = super().send_probe_packet_and_get_result(packet, target, port, timeout)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            return PortState.Closed
