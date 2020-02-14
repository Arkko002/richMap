from richMap.port_scanning.port_result import PortState
from richMap.port_scanning.response_packet import TcpFlags
from richMap.port_scanning.scans.abstract_scan import AbstractScan
from richMap.util.packet_generator import PacketGenerator


class MaimonScan(AbstractScan):
    def get_scan_result(self, target, port, timeout):
        packet = PacketGenerator.generate_tcp_packet(port, fin=1, ack=1)
        result = super().send_probe_packet_and_get_result(packet, target, port, timeout)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            return PortState.Closed
