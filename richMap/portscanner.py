import socket
import packetgenerator
import os
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
    def perform_scan(self, target: str, port_range: str, scan_type) -> list:
        """Base function to be called when performing scan"""

        return_list = []
        ports = port_range.split("-")

        scans = {
            "T": self._tcp_scan,
            "S": self._syn_scan,
            "U": self._udp_scan,
            "A": self._ack_scan,
            "F": self._fin_scan,
            "X": self._xmas_scan,
            "N": self._null_scan
        }

        if scan_type != "T" and scan_type != "U":
            soc = self.__create_raw_socket("TCP")
        elif scan_type == "T":
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif scan_type == "U":
            soc = self.__create_raw_socket("UDP")
        soc_icmp = self.__create_raw_socket("ICMP")

        for port in range(int(ports[0]), int(ports[1]) + 1):
            return_list.append(scans[scan_type](target, port, soc, soc_icmp))

        return return_list

    def _tcp_scan(self, target: str, port, soc: socket, *args) -> str:
        """Performs a TCP scan on a given target and port"""

        status = soc.connect_ex((target, port))
        if status == 0:
            soc.shutdown(socket.SHUT_RDWR)
            return "Open - " + str(port)


    # TODO Make a function that will handle sending and reciving packets, threading
    def _syn_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs a SYN scan on a given target and port"""

        soc.settimeout(2.99)
        soc_icmp.settimeout(2.99)
        packet = packetgenerator.generate_tcp_packet(port, syn=1)
        soc.sendto(packet, (target, port))

        tcp_result = self.__await_response(soc)
        icmp_result = self.__await_response(soc_icmp)

        if tcp_result == False:
            for i in range(3):
                soc.sendto(packet, (target, port))
                tcp_res = self.__await_response(soc)
                if tcp_res != False:
                    break
                else:
                    return "Filtered " + str(port)

        header = packetgenerator.unpack_tcp_packet(tcp_result[20:40])
        tcp_flags = self.__check_tcp_flags(bin(header[5])[2:])

        if TcpFlags.SYN in tcp_flags and TcpFlags.ACK in tcp_flags and len(tcp_flags) == 2:
            return "Open " + str(port)
        elif TcpFlags.SYN in tcp_flags and len(tcp_flags) == 1:
            return "Open " + str(port)
        elif TcpFlags.RST in tcp_flags and len(tcp_flags) == 1:
            return "Closed " + str(port)

        if icmp_result != False:
            icmp_header = packetgenerator.unpack_icmp_packet(icmp_result[20:28])
            if icmp_header[0] == 3:
                return  "Filtered " + str(port)


    def _udp_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs a UDP scan on a given target and port"""

        soc_icmp.settimeout(10.99)
        soc.settimeout(10.99)

        packet = packetgenerator.generate_udp_packet(port)
        soc.sendto(packet, (target, port))

        icmp_result = self.__await_response(soc_icmp)

        if icmp_result != False:
            icmp_header = packetgenerator.unpack_icmp_packet(icmp_result[20:28])

            if icmp_header[0] == 3 and icmp_header[1] == 3:
                return "Closed " + str(port)
            elif icmp_header[0] == 3 and icmp_header[1] != 3:
                return "Filtered " + str(port)
        else:
            return "Open | filtered " + str(port)

    def _ack_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs an ACK scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port, ack=1)
        soc.sendto(packet, (target,port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Filtered " + str(port)

        header = packetgenerator.unpack_tcp_packet(rec_packet[20:40])
        tcp_flags = self.__check_tcp_flags(bin(header[5])[2:])

        if TcpFlags.RST in tcp_flags:
            return "Unfiltered " + str(port)

    def _fin_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs an FIN scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port, fin=1)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Open|filtered " + str(port)

    def _xmas_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs an Xmas scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port, fin=1, urg=1, psh=1)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Open|filtered " + str(port)

    def _null_scan(self, target: str, port, soc: socket, soc_icmp: socket) -> str:
        """Performs an null scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Open|filtered " + str(port)

    def __await_response(self, soc: socket):
        """Returns False if socket timed out, otherwise returns incoming packet"""

        try:
            recv_packet = soc.recv(65535)
        except socket.timeout:
            return False
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
            print("You need administrator rights to run this scan")
            raise OSError

        if soc_type == "TCP":
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        elif soc_type == "UDP":
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        elif soc_type == "ICMP":
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        else:
            return

        return soc
