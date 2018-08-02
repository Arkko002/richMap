import socket
import packetgenerator

class Scanner(object):
    """Object that holds all of the scanning methods"""

    def tcp_scan(target: str, port_range: str) -> list:
        """Performs a TCP scan on given targe and port range"""
        return_list = []
        ports = port_range.split("-")
        for port in range(ports[0], ports[1]):
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            status = soc.connect_ex((target, port))
            if status == 0:
                soc.shutdown(socket.SHUT_RDWR)
                return_list.append(port)        
        return return_list

    def syn_scan(target: str, port_range: str) -> list:
        """Perfoms a SYN scan on a given target and port range"""
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1])):
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            packet = packetgenerator.packetgenerator.generate_tcp_packet(port, syn=1)

    def udp_scan(taget: str, port_range: str) -> list:
        """Performs a UDP scan on a given target and port range"""
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1])):
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            