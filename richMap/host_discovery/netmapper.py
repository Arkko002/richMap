import os
import re
import socket
from richMap.util.packetgenerator import PacketGenerator
import random
from time import sleep


class Netmapper(object):
    """Used to discover live hosts on the network"""

    def __init__(self, network_ip: str, scan_type: str, net_interface: str = None):
        self.network_ip = network_ip
        self.scan_type = scan_type

        if net_interface is None:
            self.net_interface = self.__get_default_interface()
        else:
            self.net_interface = net_interface

        if "A" in scan_type:
            self.soc = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

            if scan_type == "As":
                spoofed_mac_a = random.randrange(1, 255)
                spoofed_mac_b = random.randrange(1, 255)
                spoofed_mac_c = random.randrange(1, 255)
                spoofed_mac_d = random.randrange(1, 255)
                spoofed_mac_e = random.randrange(1, 255)
                spoofed_mac_f = random.randrange(1, 255)

                self.spoofed_src_mac = [
                    spoofed_mac_a,
                    spoofed_mac_b,
                    spoofed_mac_c,
                    spoofed_mac_d,
                    spoofed_mac_e,
                    spoofed_mac_f
                ]

    def __del__(self):
        self.soc.close()

    # TODO Make all of this DRY
    # TODO Make net_interface optional
    def map_network(self):
        """Performs a specified type of scan on a given IP range"""

        scans = {
            "P": self._ping_scan,
            "A": self._arp_scan,
            "As": self._arp_stealth_scan,
            "Ap": self._arp_passive_scan
        }

        if self.scan_type not in scans:
            return "Wrong scan type specified"

        index = self.network_ip.rfind(".")
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        return_list = []

        if r.match(self.network_ip):
            for ip in range(1, 256):
                scan_result = scans[self.scan_type](
                    self.network_ip[:index + 1] + str(ip))
                if scan_result is not None:
                    return_list.append(
                        self.network_ip[:index + 1] + str(ip) + " " + scan_result + " Host Up")
        else:
            return "The given IP is not in the correct format"

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
        self.soc.send(packet)
        arp_result = self._await_arp_response()

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
                    rec_mac_adr = rec_mac_adr + \
                        str(hex(rec_arp_header[i])).replace("0x", "") + ":"
                return rec_mac_adr
        else:
            return None

    def _arp_stealth_scan(self, ip: str):
        """Performs stealth ARP scan on the target network"""

        packet = PacketGenerator.generate_spoofed_eth_arp_packet(
            dst_ip=ip, eth_src_mac=self.spoofed_src_mac)
        time_to_sleep = random.randrange(120, 720)

        sleep(time_to_sleep)
        self.soc.send(packet)
        return self._await_arp_response()

    def _arp_passive_scan(self):
        return

    def _await_arp_response(self):
        try:
            rec_packet = self.soc.recv(1024)
        except socket.timeout:
            return
        return rec_packet

    @staticmethod
    def __get_default_interface():
        interfaces = os.listdir("/sys/class/net")
        return interfaces[0]
