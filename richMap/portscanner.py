import socket
from packetgenerator import PacketGenerator
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


class PortScanner(object):

    # TODO Make all of this DRY
    # TODO Threading
    def perform_scan(self, target: str, scan_type, port_range: str = None):
        """Base function to be called when performing scan"""

        return_list = []
        if port_range is None:
            port_range = "1-65535"
        ports = port_range.split("-")

        scans = {
            "T": self._tcp_scan,
            "S": self._syn_scan,
            "U": self._udp_scan,
            "A": self._ack_scan,
            "F": self._fin_xmas_null_scan,
            "X": self._fin_xmas_null_scan,
            "N": self._fin_xmas_null_scan,
            "M": self._maimon_scan,
            "W": self._window_scan
        }

        if scan_type not in scans:
            return "Wrong scan type specified"

        if scan_type != "T" and scan_type != "U":
            soc = self.__create_raw_socket("TCP")
        elif scan_type == "T":
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif scan_type == "U":
            soc = self.__create_raw_socket("UDP")
        elif scan_type == "F" or scan_type == "X" or scan_type == "N":
            global special_scan_type
            special_scan_type = scan_type

        soc_icmp = self.__create_raw_socket("ICMP")

        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if r.match(target):
            for port in range(int(ports[0]), int(ports[1]) + 1):
                return_list.append(scans[scan_type](target, port, soc, soc_icmp))
        else:
            return "The given IP is not in the correct format"

        soc.close()
        soc_icmp.close()
        return return_list

    def _tcp_scan(self, target: str, port, soc: socket, *args) -> str:
        """Performs a TCP scan on a given target and port"""

        status = soc.connect_ex((target, port))
        if status == 0:
            soc.shutdown(socket.SHUT_RDWR)
            return "Open " + str(port)
        else:
            return "Closed " + str(port)

    def _syn_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs a SYN scan on a given target and port"""

        soc.settimeout(2.99)
        soc_icmp.settimeout(2.99)
        packet = PacketGenerator.generate_tcp_packet(port, syn=1)
        soc.sendto(packet, (target, port))

        tcp_result = self.__await_response(soc)
        icmp_result = self.__await_response(soc_icmp)

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(soc, soc_icmp, packet, target, port)
            if tcp_result is None and icmp_result is None:
                return "Filtered " + str(port)

        header = PacketGenerator.unpack_tcp_header(tcp_result)
        tcp_flags = self.__check_tcp_flags(bin(header[5])[2:])

        if TcpFlags.SYN in tcp_flags and TcpFlags.ACK in tcp_flags and len(tcp_flags) == 2:
            return "Open " + str(port)
        elif TcpFlags.SYN in tcp_flags and len(tcp_flags) == 1:
            return "Open " + str(port)
        elif TcpFlags.RST in tcp_flags and len(tcp_flags) == 1:
            return "Closed " + str(port)

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)
            if icmp_header[0] == 3:
                return "Filtered " + str(port)

    # TODO
    def _udp_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs a UDP scan on a given target and port"""

        soc_icmp.settimeout(10.99)
        soc.settimeout(10.99)

        packet = PacketGenerator.generate_udp_packet(port)
        soc.sendto(packet, (target, port))

        icmp_result = self.__await_response(soc_icmp)

        if icmp_result is not None:
            icmp_header = PacketGenerator.unpack_icmp_header(icmp_result)

            if icmp_header[0] == 3 and icmp_header[1] == 3:
                return "Closed " + str(port)
            elif icmp_header[0] == 3 and icmp_header[1] != 3:
                return "Filtered " + str(port)
        else:
            return "Open | Filtered " + str(port)

    def _ack_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs an ACK scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        soc.sendto(packet, (target, port))

        tcp_result = self.__await_response(soc)
        icmp_result = self.__await_response(soc_icmp)

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(soc, soc_icmp, packet, target, port)
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

    def _fin_xmas_null_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs either FIN, Xmas, or null scan on a given target and port"""

        if special_scan_type == "F":
            packet = PacketGenerator.generate_tcp_packet(port, fin=1)
        elif special_scan_type == "X":
            packet = PacketGenerator.generate_tcp_packet(port, fin=1, urg=1, psh=1)
        elif special_scan_type == "N":
            packet = PacketGenerator.generate_tcp_packet(port)

        soc.sendto(packet, (target, port))

        tcp_result = self.__await_response(soc)
        icmp_result = self.__await_response(soc_icmp)

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(soc, soc_icmp, packet, target, port)
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

    def _window_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs window scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, ack=1)
        soc.sendto(packet, (target, port))

        tcp_result = self.__await_response(soc)
        icmp_result = self.__await_response(soc_icmp)

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(soc, soc_icmp, packet, target, port)
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

    def _maimon_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs Maimon's scan on a given target and port"""

        packet = PacketGenerator.generate_tcp_packet(port, fin=1, ack=1)
        soc.sendto(packet, (target, port))

        tcp_result = self.__await_response(soc)
        icmp_result = self.__await_response(soc_icmp)

        if tcp_result is None and icmp_result is None:
            tcp_result, icmp_result = self.__resend_probe_packet(soc, soc_icmp, packet, target, port)
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

    def __resend_probe_packet(self, soc: socket, soc_icmp: socket, packet, target, port):
        """Resend's the probe packet, returns the response packets or None in case of no response"""

        for i in range(3):
            soc.sendto(packet, (target, port))
            tcp_result = self.__await_response(soc)
            icmp_result = self.__await_response(soc_icmp)
            if tcp_result is not None or icmp_result is not None:
                return tcp_result, icmp_result
            else:
                return None

    @staticmethod
    def __await_response(soc: socket):
        """Returns None if socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = soc.recv(65535)
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

    @staticmethod
    def __create_raw_socket(soc_type: str):
        if os.getuid() != 0:
            return "You need administrator rights to run this scan"

        if soc_type == "TCP":
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        elif soc_type == "UDP":
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        elif soc_type == "ICMP":
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            return

        return soc
