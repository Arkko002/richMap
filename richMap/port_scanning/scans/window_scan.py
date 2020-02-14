from richMap.port_scanning.port_result import PortState
from richMap.port_scanning.response_packet import TcpFlags
from richMap.port_scanning.scans.abstract_port_scan import AbstractPortScan
from richMap.util.packet_generator import PacketGenerator


class WindowPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout):
        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        result = super().send_probe_packet_and_get_result(packet, target, port, 3.0)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            window_size = result.get_window_size()
            if window_size > 0:
                return PortState.Open
            elif window_size == 0:
                return PortState.Closed
