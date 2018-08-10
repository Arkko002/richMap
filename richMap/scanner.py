import socket
import packetgenerator
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


class Scanner(object):

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
            soc = self.__create_tcp_raw_socket()

        for port in range(int(ports[0]), int(ports[1]) + 1):
            return_list.append(scans[scan_type](self=self, target=target, port=port, soc=soc))

        return return_list

    def _tcp_scan(self, target: str, port) -> str:
        """Performs a TCP scan on a given target and port"""

        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        status = soc.connect_ex((target, port))
        if status == 0:
            soc.shutdown(socket.SHUT_RDWR)
            return "Open - " + str(port)

    def _syn_scan(self, target: str, port, soc) -> str:
        """Performs a SYN scan on a given target and port"""

        soc.settimeout(2.99)
        packet = packetgenerator.generate_tcp_packet(port, syn=1)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Filtered " + str(port)

        header = packetgenerator.unpack_tcp_packet(rec_packet[20:40])
        tcp_flags = self.__check_tcp_flags(bin(header[5])[2:])

        if TcpFlags.SYN in tcp_flags and TcpFlags.ACK in tcp_flags and len(tcp_flags) == 2:
            return "Open " + str(port)

        if TcpFlags.SYN in tcp_flags and len(tcp_flags) == 1:
            return "Open " + str(port)

    def _udp_scan(self, target: str, port) -> str:
        """Performs a UDP scan on a given target and port"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            soc_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError:
            print("You need administrator rights to run this scan")
            raise
        soc_recv.settimeout(10.99)

        packet = packetgenerator.generate_udp_packet(port)
        soc.sendto(packet, (target, port))

        try:
            rec_packet = soc_recv.recv(1024)
        except socket.timeout:
            soc.sendto(packet, (target, port))
            try:
                rec_packet = soc_recv.recv(1024)
            except socket.timeout:
                return "Open | filtered" + str(port)

        icmp_header = packetgenerator.unpack_icmp_packet(rec_packet[20:28])

        if icmp_header[0] == 3 and icmp_header[1] != 3:
            return "Filtered " + str(port)

    def _ack_scan(self, target: str, port, soc) -> str:
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

    def _fin_scan(self, target: str, port, soc) -> str:
        """Performs an FIN scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port, fin=1)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Open|filtered " + str(port)

    def _xmas_scan(self, target: str, port, soc) -> str:
        """Performs an Xmas scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port, fin=1, urg=1, psh=1)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Open|filtered " + str(port)

    def _null_scan(self, target: str, port: str, soc) -> str:
        """Performs an null scan on a given target and port"""

        packet = packetgenerator.generate_tcp_packet(port)
        soc.sendto(packet, (target, port))
        try:
            rec_packet = soc.recv(65535)
        except socket.timeout:
            return "Open|filtered " + str(port)

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
    def __create_tcp_raw_socket():
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            print("You need administrator rights to run this scan")
            raise
        return soc
