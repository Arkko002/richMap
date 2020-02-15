from abc import ABC, abstractmethod

from richMap.abstract_base_scanner import AbstractBaseScanner
from richMap.port_scanning.port_result import PortState
from richMap.port_scanning.response_packet import TcpResponsePacket, TcpFlags
from richMap.util.packet_generator import PacketGenerator


class AbstractPortScan(AbstractBaseScanner):
    @abstractmethod
    def get_scan_result(self, target, port, timeout) -> PortState:
        pass

    def send_probe_packet_and_get_result(self, packet, target, port, timeout):
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
