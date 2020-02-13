from richMap.port_scanning.scans.abstract_scan import AbstractScan


class UdpScan(AbstractScan):
    def get_scan_result(self, target, port, timeout):
        packet = PacketGenerator.generate_udp_packet(port)
        self.soc.sendto(packet, (target, port))

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3 and icmp_header[1] == 3:
                return PortState.Closed
            elif icmp_header[0] == 3 and icmp_header[1] != 3:
                return PortState.Filtered
        else:
            return PortState.OpenFiltered
