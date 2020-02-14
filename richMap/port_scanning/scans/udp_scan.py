from richMap.port_scanning.port_result import PortState
from richMap.port_scanning.scans.abstract_port_scan import AbstractPortScan
from richMap.util.packet_generator import PacketGenerator


class UdpPortScan(AbstractPortScan):
    def get_scan_result(self, target, port, timeout):
        packet = PacketGenerator.generate_udp_packet(port)
        return self.__send_udp_probe_packet_and_get_result(packet, target, port, timeout)

    def __send_udp_probe_packet_and_get_result(self, packet, target, port, timeout):
        results = self.soc.send_packet_and_return_result(packet, target, port, timeout)

        if results.icmp_res is None and results.soc_res is None:
            return PortState.Filtered

        if results.icmp_res is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(results.icmp_res)

            if icmp_header[0] == 3 and icmp_header[1] == 3:
                return PortState.Closed
            elif icmp_header[0] == 3 and icmp_header[1] != 3:
                return PortState.Filtered
        else:
            return PortState.OpenFiltered
