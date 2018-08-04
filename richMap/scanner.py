import socket
import packetgenerator
import struct

class Scanner(object):
    """Object that holds all of the scanning methods"""

    def tcp_scan(target: str, port_range: str) -> list:
        """Performs a TCP scan on given targe and port range"""

        return_list = []
        ports = port_range.split("-")
        for port in range(ports[0], ports[1] + 1):
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            status = soc.connect_ex((target, port))
            if status == 0:
                soc.shutdown(socket.SHUT_RDWR)
                return_list.append(port)        
        return return_list

    def syn_scan(target: str, port_range: str) -> list:
        """Perfoms a SYN scan on a given target and port range"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            print("You need administrator rights to run this scan")
            return
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1] + 1)):
            packet = packetgenerator.packetgenerator.generate_tcp_packet(port, syn=1)
            

    def udp_scan(target: str, port_range: str) -> list:
        """Performs a UDP scan on a given target and port range"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            soc_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except OSError:
            print("You need administrator rights to run this scan")
            return
        soc_recv.settimeout(0.99999)
        soc_recv.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
        return_list = []
        ports = port_range.split("-")

        for port in range(int(ports[0]), int(ports[1] + 1)):
            packet = packetgenerator.packetgenerator.generate_udp_packet(port)
            soc.sendto(packet, (target, port))
            try:
                rec_packet, adr = soc_recv.recvfrom(1024)
            except socket.timeout:
                return_list.append(port)
                continue
            if adr == taget:
                icmp_header = rec_packet[20:28]
                icmp_type, icmp_code = struct.unpack('bb', icmp_header)
                if icmp_type == 3 and icmp_code == 3:
                    continue
    
    def ack_scan(target: str, port_range: str) -> list:
        """Performs an ACK scan on a given target and port range"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            print("You need administrator rights to run this scan")
            return
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1] + 1)):
            packet = packetgenerator.packetgenerator.generate_tcp_packet(port, ack=1)

    def fin_scan(target: str, port_range: str) -> list:
        """Performs an FIN scan on a given target and port range"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            print("You need administrator rights to run this scan")
            return
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1] + 1)):
            packet = packetgenerator.packetgenerator.generate_tcp_packet(port, fin=1)

    def xmas_scan(target: str, port_range: str) -> list:
        """Performs an Xmas scan on a given target and port range"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            print("You need administrator rights to run this scan")
            return
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1] + 1)):
            packet = packetgenerator.packetgenerator.generate_tcp_packet(port, fin=1, urg=1, psh=1)

    def null_scan(target: str, port_range: str) -> list:
        """Performs an null scan on a given target and port range"""

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            print("You need administrator rights to run this scan")
            return
        return_list = []
        ports = port_range.split("-")
        for port in range(int(ports[0]), int(ports[1] + 1)):
            packet = packetgenerator.packetgenerator.generate_tcp_packet(port)