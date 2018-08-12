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

        if "A" in scan_type:
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
        if scan_type == "As":
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
        else:
            spoofed_src_mac = []

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
                if scans[scan_type](network_ip[:index + 1] + str(ip), s, spoofed_src_mac):
                    return_list.append(network_ip[:index + 1] + str(ip))
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
        return self._send_arp_packet(s, packet)

    def _arp_stealth_scan(self, ip: str, s: socket, spoofed_mac_adr):
        """Performs stealth ARP scan on the target network"""

        packet = packetgenerator.generate_spoofed_eth_arp_packet(dst_ip=ip, eth_src_mac=spoofed_mac_adr)
        time_to_sleep = random.randrange(120, 720)

        sleep(time_to_sleep)
        return self._send_arp_packet(s, packet)

    def _arp_passive_scan(self):
        return

    def _send_arp_packet(self, s: socket, packet):
        s.send(packet)
        try:
            rec_packet = s.recv(1024)
        except socket.timeout:
            return False

        rec_header = packetgenerator.unpack_eth_arp_packet(rec_packet)
        if rec_header[12] == 0x08 and rec_header[13] == 0x06:
            if rec_header[21] == 0x02:
                return True
