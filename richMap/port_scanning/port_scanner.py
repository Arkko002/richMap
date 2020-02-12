import socket

from richMap.port_scanning import socket_type
from richMap.port_scanning.host_result import HostResult
from richMap.port_scanning.port_scanner_socket import PortScannerSocket
from richMap.port_scanning.response_packet import TcpResponsePacket, TcpFlags
from richMap.port_scanning.socket_type import SocketType
from richMap.util.packet_generator import PacketGenerator
from richMap.scan_types import ScanTypes
from richMap.port_scanning.port_result import PortState, PortResult
import re
from enum import Enum

class PortScanner(object):
    def __init__(self, target: str, scan_type: ScanTypes, port_range):
        self.target = target
        self.scan_type = scan_type
        self.port_range = port_range.split("-")

        if scan_type == ScanTypes.T:
            self.soc = PortScannerSocket(SocketType.TCP)
        elif scan_type == ScanTypes.U:
            self.soc = PortScannerSocket(SocketType.UDP)
        else:
            self.soc = PortScannerSocket(SocketType.TCPRaw)

    def __del__(self):
        self.soc.close_sockets()

    def perform_scan(self):
        """Base function to be called when performing scan"""

        scans = {
            ScanTypes.T: self._tcp_scan,
            ScanTypes.S: self._syn_scan,
            ScanTypes.U: self._udp_scan,
            ScanTypes.A: self._ack_scan,
            ScanTypes.F: self._fin_scan,
            ScanTypes.X: self._xmas_scan,
            ScanTypes.N: self._null_scan,
            ScanTypes.M: self._maimon_scan,
            ScanTypes.W: self._window_scan
        }

        if self.scan_type not in scans:
            return "Wrong scan type specified"

        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if r.match(self.target) is False:
            return "The given IP is not in the correct format"

        host_result = HostResult(self.target, self.scan_type)
        scan = scans[self.scan_type]

        for port in range(int(self.port_range[0]), int(self.port_range[1]) + 1):
            port_state = scan(self.target, port)
            port_result = PortResult(port, port_state)

            host_result.port_results.append(port_result)

        return host_result

    def _tcp_scan(self, target: str, port) -> PortState:
        """Performs a TCP scan on a given target and port"""

        if self.soc.try_connecting_to_port(target, port):
            return PortState.Open
        else:
            return PortState.Closed

    def _syn_scan(self, target: str, port) -> PortState:
        """Performs a SYN scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, syn=1)
        result = self.__send_probe_packet_and_get_result(packet, target, port, 3.0)

        if result is PortState:
            return result

        if TcpFlags.SYN in result.tcp_flags and TcpFlags.ACK in result.tcp_flags and len(result.tcp_flags) == 2:
            return PortState.Open
        elif TcpFlags.SYN in result.tcp_flags and len(result.tcp_flags) == 1:
            return PortState.Open
        elif TcpFlags.RST in result.tcp_flags and len(result.tcp_flags) == 1:
            return PortState.Closed

    # TODO
    def _udp_scan(self, target: str, port) -> PortState:
        """Performs a UDP scan on a given target and port"""

        self.soc_icmp.settimeout(10.99)
        self.soc.settimeout(10.99)

        packet = PacketGenerator.generate_udp_packet(port)
        self.soc.sendto(packet, (target, port))

        icmp_result = self.__await_response()

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3 and icmp_header[1] == 3:
                return PortState.Closed
            elif icmp_header[0] == 3 and icmp_header[1] != 3:
                return PortState.Filtered
        else:
            return PortState.OpenFiltered

    def _ack_scan(self, target: str, port) -> PortState:
        """Performs an ACK scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        result = self.__send_probe_packet_and_get_result(packet, target, port, 3.0)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            return PortState.Unfiltered

    def _fin_scan(self, target: str, port) -> PortState:
        packet = PacketGenerator.generate_tcp_packet(port, fin=1)

        return self._fin_xmas_null_scan(target, port, packet)

    def _xmas_scan(self, target: str, port) -> PortState:
        packet = PacketGenerator.generate_tcp_packet(port, fin=1, urg=1, psh=1)

        return self._fin_xmas_null_scan(target, port, packet)

    def _null_scan(self, target: str, port) -> PortState:
        packet = PacketGenerator.generate_tcp_packet(port)

        return self._fin_xmas_null_scan(target, port, packet)

    def _fin_xmas_null_scan(self, target: str, port, packet) -> PortState:
        """Code shared by FIN, XMAS, NULL scan. Should only be called
        from within a function that specifies the scan type / packet flags"""
        result = self.__send_probe_packet_and_get_result(packet, target, port, 3.0)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            return PortState.Closed

    def _window_scan(self, target: str, port) -> PortState:
        """Performs window scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        result = self.__send_probe_packet_and_get_result(packet, target, port, 3.0)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            window_size = result.get_window_size()
            if window_size > 0:
                return PortState.Open
            elif window_size == 0:
                return PortState.Closed

    def _maimon_scan(self, target: str, port) -> PortState:
        """Performs Maimon's scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, fin=1, ack=1)
        result = self.__send_probe_packet_and_get_result(packet, target, port, 3.0)

        if result is PortState:
            return result

        if TcpFlags.RST in result.tcp_flags:
            return PortState.Closed

    # TODO
    def _ip_protocol_scan(self, target: str, soc: socket, soc_icmp: socket):
        return

    def __send_probe_packet_and_get_result(self, packet, target, port, timeout):
        """Sends probe packet, returns PortState if probe failed, otherwise returns ResponsePacket"""
        results = self.soc.send_packet_and_return_result(packet, target, port, timeout)

        if results.icmp_res is None and results.soc_res is None:
            return PortState.Filtered

        if results.icmp_res is not None:
            if self.__is_destination_unreachable(results.icmp_res):
                return PortState.Filtered

        if results.soc_res is not None:
            tcp_flags = self.__get_tcp_flags(results.soc_res)
            tcp_header = PacketGenerator.unpack_tcp_header(results.soc_res)
            return TcpResponsePacket(tcp_flags, tcp_header)

    def __get_tcp_flags(self, packet):
        tcp_header = PacketGenerator.unpack_tcp_header(packet)
        return self.__check_tcp_flags(bin(tcp_header[5])[2:])

    @staticmethod
    def __check_tcp_flags(flags_bin):
        while len(flags_bin) < 8:
            flags_bin = "0" + flags_bin

        return_list = []
        for i in range(0, len(flags_bin)):
            if flags_bin[i] == "1":
                return_list.append(TcpFlags(i))
        return return_list

    @staticmethod
    def __is_destination_unreachable(icmp_packet):
        if icmp_packet is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_packet)

            if icmp_header[0] == 3:
                return True
            return False