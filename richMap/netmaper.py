import os
import re
import socket
import packetgenerator
import random
from time import sleep


class Netmaper(object):
    """Used to discover live hosts on the network"""

    # TODO Make all of this DRY
    def map_network(self, network_ip: str, scan_type: str, net_interface: str):
        """Performs a specified type of scan on a given IP range"""

        return_list = []

        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        except OSError:
            print("You need administrator rights to run this scan")
            raise
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.settimeout(0.05)
        try:
            s.bind((net_interface, 0))
        except OSError:
            print("No such interface")
            raise

        spoofed_mac_a = random.randrange(1, 255)
        spoofed_mac_b = random.randrange(1, 255)
        spoofed_mac_c = random.randrange(1, 255)
        spoofed_mac_d = random.randrange(1, 255)
        spoofed_mac_e = random.randrange(1, 255)
        spoofed_mac_f = random.randrange(1, 255)

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

        index = network_ip.rfind(".")
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if r.match(network_ip):
            for ip in range(1, 256):
                scan_result = scans[scan_type](network_ip[:index + 1] + str(ip), s, spoofed_src_mac)
                if scan_result is not None:
                    return_list.append(network_ip[:index + 1] + str(ip) + " " + scan_result + " Host Up")
        else:
            print("The given IP is not in the correct format")
            return

        return return_list

    def _ping_scan(self, network_ip: str, *args):
        """Simple ping on the target"""

        response = os.system("ping -c 1 " + network_ip)
        if response == 0:
            return True

    def _arp_scan(self, ip: str, s: socket, *args):
        """Performs an ARP scan on the target network"""

        packet = packetgenerator.generate_arp_packet(dst_ip=ip)
        arp_result = self._await_arp_response(s, packet)

        if arp_result is None:
            return None

        rec_eth_header = packetgenerator.unpack_eth_header(arp_result)
        rec_arp_header = packetgenerator.unpack_arp_header(arp_result)

        if rec_eth_header[12] == 0x08 and rec_eth_header[13] == 0x06:
            if rec_arp_header[4] == 0x02:
                rec_mac_adr = ""
                for i in range(5,11):
                    if len(str(rec_arp_header[i])) == 1:
                        rec_mac_adr = rec_mac_adr + "0"
                    rec_mac_adr = rec_mac_adr + str(hex(rec_arp_header[i])).replace("0x", "") + ":"
                return rec_mac_adr
        else:
            return None

    def _arp_stealth_scan(self, ip: str, s: socket, spoofed_mac_adr):
        """Performs stealth ARP scan on the target network"""

        packet = packetgenerator.generate_spoofed_eth_arp_packet(dst_ip=ip, eth_src_mac=spoofed_mac_adr)
        time_to_sleep = random.randrange(120, 720)

        sleep(time_to_sleep)
        return self._await_arp_response(s, packet)

    def _arp_passive_scan(self):
        return

    def _await_arp_response(self, s: socket, packet):
        s.send(packet)
        try:
            rec_packet = s.recv(1024)
        except socket.timeout:
            return
        return rec_packet

