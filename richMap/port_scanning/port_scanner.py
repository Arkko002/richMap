import socket
from richMap.util.packet_generator import PacketGenerator
from richMap.scan_types import ScanTypes
import os
import re
from enum import Enum


class TcpFlags(Enum):
    CWR = 0
    ECE = 1
    URG = 2
    ACK = 3
    PSH = 4
    RST = 5
    SYN = 6
    FIN = 7


class SocketType(Enum):
    Error = 0
    UDP = 1
    TCP = 2
    ICMP = 3


class PortScanner(object):
    def __init__(self, target: str, scan_type: ScanTypes, port_range):
        self.target = target
        self.scan_type = scan_type
        self.port_range = port_range.split("-")

        self.socket_scan_type = {
            ScanTypes.T: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
            ScanTypes.U: self.__create_raw_socket(SocketType.UDP),
        }

        if scan_type == ScanTypes.S or scan_type == ScanTypes.U:
            self.soc_icmp = self.__create_raw_socket(SocketType.ICMP)

        if scan_type not in self.socket_scan_type:
            self.soc = self.__create_raw_socket(SocketType.TCP)

    def __del__(self):
        self.soc.close()
        self.soc_icmp.close()

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

        return_list = []

        if r.match(self.target) is False:
            return "The given IP is not in the correct format"

        for port in range(int(self.port_range[0]), int(self.port_range[1]) + 1):
            return_list.append(scans[self.scan_type](self.target, port))

        return return_list

    def _tcp_scan(self, target: str, port) -> bool:
        """Performs a TCP scan on a given target and port"""

        status = self.soc.connect_ex((target, port))
        if status == 0:
            self.soc.shutdown(socket.SHUT_RDWR)
            return True
        else:
            return False

    def _syn_scan(self, target: str, port) -> bool:
        """Performs a SYN scan on a given target and port"""

        self.soc.settimeout(2.99)
        self.soc_icmp.settimeout(2.99)
        packet = PacketGenerator.generate_tcp_packet(port, syn=1)
        self.soc.sendto(packet, (target, port))

        tcp_result = self.__await_response()
        icmp_result = self.__await_response()

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(packet, target, port)
            if tcp_result is None and icmp_result is None:
                return False

        header = PacketGenerator.unpack_tcp_header(tcp_result)
        tcp_flags = self.__check_tcp_flags(bin(header[5])[2:])

        if TcpFlags.SYN in tcp_flags and TcpFlags.ACK in tcp_flags and len(tcp_flags) == 2:
            return True
        elif TcpFlags.SYN in tcp_flags and len(tcp_flags) == 1:
            return True
        elif TcpFlags.RST in tcp_flags and len(tcp_flags) == 1:
            return False

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)
            if icmp_header[0] == 3:
                return False

    # TODO
    def _udp_scan(self, target: str, port) -> bool:
        """Performs a UDP scan on a given target and port"""

        self.soc_icmp.settimeout(10.99)
        self.soc.settimeout(10.99)

        packet = PacketGenerator.generate_udp_packet(port)
        self.soc.sendto(packet, (target, port))

        icmp_result = self.__await_response()

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3 and icmp_header[1] == 3:
                return "Closed " + str(port)
            elif icmp_header[0] == 3 and icmp_header[1] != 3:
                return "Filtered " + str(port)
        else:
            return "Open | Filtered " + str(port)

    def _ack_scan(self, target: str, port) -> bool:
        """Performs an ACK scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        self.soc.sendto(packet, (target, port))

        tcp_result = self.__await_response()
        icmp_result = self.__await_response()

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(packet, target, port)
            if tcp_result is None and icmp_result is None:
                return "Filtered " + str(port)

        if tcp_result is not None:
            tcp_header = PacketGenerator.unpack_tcp_header(tcp_result)
            tcp_flags = self.__check_tcp_flags(bin(tcp_header[5])[2:])

            if TcpFlags.RST in tcp_flags:
                return "Unfiltered " + str(port)

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3:
                return "Filtered " + str(port)

    def _fin_scan(self, target: str, port) -> bool:
        packet = PacketGenerator.generate_tcp_packet(port, fin=1)

        return self._fin_xmas_null_scan(target, port, packet)

    def _xmas_scan(self, target: str, port) -> bool:
        packet = PacketGenerator.generate_tcp_packet(port, fin=1, urg=1, psh=1)

        return self._fin_xmas_null_scan(target, port, packet)

    def _null_scan(self, target: str, port) -> bool:
        packet = PacketGenerator.generate_tcp_packet(port)

        return self._fin_xmas_null_scan(target, port, packet)

    def _fin_xmas_null_scan(self, target: str, port, packet) -> bool:
        """Code shared by FIN, XMAS, NULL scan. Should only be called
        from within a function that specifies the scan type / packet flags"""
        self.soc.sendto(packet, (target, port))

        tcp_result = self.__await_response()
        icmp_result = self.__await_response()

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(packet, target, port)
            if tcp_result is None and icmp_result is None:
                return "Open | filtered " + str(port)

        if tcp_result is not None:
            tcp_header = PacketGenerator.unpack_tcp_header(tcp_result)
            tcp_flags = self.__check_tcp_flags(bin(tcp_header[5])[2:])

            if TcpFlags.RST in tcp_flags:
                return "Closed " + str(port)

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3:
                return "Filtered " + str(port)

    def _window_scan(self, target: str, port) -> bool:
        """Performs window scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        self.soc.sendto(packet, (target, port))

        tcp_result = self.__await_response()
        icmp_result = self.__await_response()

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(packet, target, port)
            if tcp_result is None and icmp_result is None:
                return "Filtered " + str(port)

        if tcp_result is not None:
            tcp_header = PacketGenerator.unpack_tcp_header(tcp_result)
            tcp_flags = self.__check_tcp_flags(bin(tcp_header[5])[2:])

            if TcpFlags.RST in tcp_flags:
                if tcp_header[6] > 0:
                    return "Open " + str(port)
                elif tcp_header[6] == 0:
                    return "Closed " + str(port)

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3:
                return "Filtered " + str(port)

    def _maimon_scan(self, target: str, port) -> bool:
        """Performs Maimon's scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, fin=1, ack=1)
        self.soc.sendto(packet, (target, port))

        tcp_result = self.__await_response()
        icmp_result = self.__await_response()

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(packet, target, port)
            if tcp_result is None and icmp_result is None:
                return "Open " + str(port)

        if tcp_result is not None:
            tcp_header = PacketGenerator.unpack_tcp_header(tcp_result)
            tcp_flags = self.__check_tcp_flags(bin(tcp_header[5])[2:])

            if TcpFlags.RST in tcp_flags:
                return "Closed " + str(port)

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3:
                return "Filtered " + str(port)

    def _ip_protocol_scan(self, target: str, soc: socket, soc_icmp: socket):
        return

    def __resend_probe_packet(self, packet, target, port):
        """Resend's the probe packet, returns the response packets or None in case of no response"""

        for i in range(3):
            self.soc.sendto(packet, (target, port))
            tcp_result = self.__await_response()
            icmp_result = self.__await_response()
            if tcp_result is not None or icmp_result is not None:
                return tcp_result, icmp_result
            else:
                return None

    def __await_response(self):
        """Returns None if socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = self.soc.recv(65535)
        except socket.timeout:
            return None
        return recv_packet

    @staticmethod
    def __check_tcp_flags(flags_bin):
        while len(flags_bin) < 8:
            flags_bin = "0" + flags_bin

        return_list = []
        for i in range(0, len(flags_bin)):
            if flags_bin[i] == "1":
                return_list.append(TcpFlags(i))
        return return_list

    def __create_raw_socket(self, soc_type: SocketType):
        if os.getuid() != 0:
            return "You need administrator rights to run this scan"

        socket_switcher = {
            SocketType.TCP: self.__get_tcp_raw_socket(),
            SocketType.UDP: self.__get_udp_raw_socket(),
            SocketType.ICMP: self.__get_icmp_raw_socket()
        }

        return socket_switcher[soc_type]

    @staticmethod
    def __get_udp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    @staticmethod
    def __get_tcp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    @staticmethod
    def __get_icmp_raw_socket():
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)