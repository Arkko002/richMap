from richMap.host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery
from richMap.util.packet_generator import PacketGenerator


class ArpDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip):
        packet = PacketGenerator.generate_arp_packet(dst_ip=target_ip)
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