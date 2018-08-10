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

        scans = {
            "P": self._ping_scan,
            "A": self._arp_scan,
            "As": self._arp_stealth_scan,
            "Ap": self._arp_passive_scan
        }

        return_list = []
        index = network_ip.rfind(".")
        r = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]"
                       "|25[0-5])$")

        if scan_type == "A":
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(0.05)
            s.bind((net_interface, 0))
            if r.match(network_ip):
                for ip in range(1, 255):
                    if scans[scan_type](network_ip[:index + 1] + str(ip), s):
                        return_list.append(network_ip[:index + 1] + str(ip))
            else:
                print("The given IP is not in the correct format")

        if scan_type == "As":
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(0.05)
            s.bind((net_interface, 0))
            spoof_a = random.randrange(1, 255)
            spoof_b = random.randrange(1, 255)
            spoof_c = random.randrange(1, 255)
            spoof_d = random.randrange(1, 255)
            spoof_e = random.randrange(1, 255)
            spoof_f = random.randrange(1, 255)

            spoofed_src_mac = [
                spoof_a,
                spoof_b,
                spoof_c,
                spoof_d,
                spoof_e,
                spoof_f
            ]
            if r.match(network_ip):
                for ip in range(1, 255):
                    if scans[scan_type](network_ip[:index + 1] + str(ip), s, spoofed_src_mac):
                        return_list.append(network_ip[:index + 1] + str(ip))
            else:
                print("The given IP is not in the correct format")
                # if scans[scan_type](network_ip[:index + 1] + str(ip)):
                #     return_list.append(network_ip[:index] + str(ip))

            return return_list

    def _ping_scan(self, network_ip: str):
        response = os.system("ping -c 1 " + network_ip)
        if response == 0:
            return True

    def _arp_scan(self, ip: str, s: socket):
        packet = packetgenerator.generate_arp_packet(dst_ip=ip)
        s.send(packet)
        try:
            rec_packet = s.recv(1024)
        except socket.timeout:
            return False

        rec_header = packetgenerator.unpack_eth_arp_packet(rec_packet)
        if rec_header[12] == 0x08 and rec_header[13] == 0x06:
            if rec_header[21] == 0x02:
                return True

    def _arp_stealth_scan(self, ip: str, s: socket, spoofed_mac_adr):
        packet = packetgenerator.generate_spoofed_eth_arp_packet(dst_ip=ip, eth_src_mac=spoofed_mac_adr)
        time_to_sleep = random.randrange(120, 720)

        sleep(time_to_sleep)
        s.send(packet)
        try:
            rec_packet = s.recv(1024)
        except socket.timeout:
            return False

        rec_header = packetgenerator.unpack_eth_arp_packet(rec_packet)
        if rec_header[12] == 0x08 and rec_header[13] == 0x06:
            if rec_header[21] == 0x02:
                return True


    def _arp_passive_scan(self):
        return

