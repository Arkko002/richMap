import os
import re
import socket
from packetgenerator import PacketGenerator
import random
from time import sleep


class Netmaper(object):
    """Used to discover live hosts on the network"""

    # TODO Make all of this DRY
    # TODO Make net_interface optional
    def map_network(self, network_ip: str, scan_type: str, net_interface: str = None):
        """Performs a specified type of scan on a given IP range"""

        if net_interface is None:
            net_interface = self.__get_default_interface()

        if "A" in scan_type:
            try:
                global s
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            except OSError:
                return "You need administrator rights to run this scan"

            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(0.05)
            try:
                s.bind((net_interface, 0))
            except OSError:
                return "No such interface"

            if "As" in scan_type:
                spoofed_mac_a = random.randrange(1, 255)
                spoofed_mac_b = random.randrange(1, 255)
                spoofed_mac_c = random.randrange(1, 255)
                spoofed_mac_d = random.randrange(1, 255)
                spoofed_mac_e = random.randrange(1, 255)
                spoofed_mac_f = random.randrange(1, 255)

                global spoofed_src_mac

                spoofed_src_mac = [
                    spoofed_mac_a,
                    spoofed_mac_b,
                    spoofed_mac_c,
                    spoofed_mac_d,
                    spoofed_mac_e,
                    spoofed_mac_f
                ]

        scans = {
            "P": self._ping_scan,
            "A": self._arp_scan,
            "As": self._arp_stealth_scan,
            "Ap": self._arp_passive_scan
        }

        if scan_type not in scans:
            return "Wrong scan type specified"

        index = network_ip.rfind(".")
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        return_list = []

        if r.match(network_ip):
            for ip in range(1, 256):
                scan_result = scans[scan_type](network_ip[:index + 1] + str(ip))
                if scan_result is not None:
                    return_list.append(network_ip[:index + 1] + str(ip) + " " + scan_result + " Host Up")
        else:
            return "The given IP is not in the correct format"

        s.close()
        return return_list

    @staticmethod
    def _ping_scan(network_ip: str):
        """Simple ping on the target"""

        response = os.system("ping -c 1 " + network_ip)
        if response == 0:
            return network_ip

    # TODO return MAC + IP after check up
    def _arp_scan(self, ip: str):
        """Performs an ARP scan on the target network"""

        packet = PacketGenerator.generate_arp_packet(dst_ip=ip)
        s.send(packet)
        arp_result = self._await_arp_response(packet)

        if arp_result is None:
            return None

        rec_eth_header = PacketGenerator.unpack_eth_header(arp_result)
        rec_arp_header = PacketGenerator.unpack_arp_header(arp_result)

        if rec_eth_header[12] == 0x08 and rec_eth_header[13] == 0x06:
            if rec_arp_header[4] == 0x02:
                rec_mac_adr = ""
                for i in range(5, 11):
                    if len(str(rec_arp_header[i])) == 1:
                        rec_mac_adr = rec_mac_adr + "0"
                    rec_mac_adr = rec_mac_adr + str(hex(rec_arp_header[i])).replace("0x", "") + ":"
                return rec_mac_adr
        else:
            return None

    def _arp_stealth_scan(self, ip: str):
        """Performs stealth ARP scan on the target network"""

        packet = PacketGenerator.generate_spoofed_eth_arp_packet(dst_ip=ip, eth_src_mac=spoofed_src_mac)
        time_to_sleep = random.randrange(120, 720)

        sleep(time_to_sleep)
        s.send(packet)
        return self._await_arp_response(packet)

    def _arp_passive_scan(self):
        return

    @staticmethod
    def _await_arp_response(packet):
        try:
            rec_packet = s.recv(1024)
        except socket.timeout:
            return
        return rec_packet

    @staticmethod
    def __get_default_interface():
        interfaces = os.listdir("/sys/class/net")
        return interfaces[0]
