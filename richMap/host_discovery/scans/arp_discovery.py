from host_discovery.model.host_discovery_result import HostDiscoveryResult
from host_discovery.scans.abstract_host_discovery import AbstractHostDiscovery


# TODO
class ArpDiscovery(AbstractHostDiscovery):
    def get_discovery_result(self, target_ip) -> HostDiscoveryResult:
        packet = PacketGenerator.generate_arp_header(dst_ip=target_ip)

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
