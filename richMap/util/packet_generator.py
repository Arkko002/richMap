from struct import pack, unpack
from socket import gethostbyname, gethostname

ICMP_HEADER_FORMAT = "!BBHHH"
TCP_HEADER_FORMAT = "!HHLLBBHHH"
IP_HEADER_FORMAT = "!BBHHHBBHII"
UDP_HEADER_FORMAT = "!HHHH"
MAC_HEADER_FORMAT = "!6B6B2B"


class PacketGenerator:

    @staticmethod
    def generate_mac_header(src_mac: str, dst_mac: str, eth_type):
        src_mac_list = src_mac.split(":")
        dst_mac_list = dst_mac.split(":")

        header = pack(MAC_HEADER_FORMAT,
                      src_mac_list[0], src_mac_list[1], src_mac_list[2], src_mac_list[3],
                      src_mac_list[4], src_mac_list[5],  # Source MAC bytes
                      dst_mac_list[0], dst_mac_list[1], dst_mac_list[2], dst_mac_list[3], dst_mac_list[4],
                      dst_mac_list[5],  # Destination MAC bytes
                      eth_type[0], eth_type[1]
                      )

        return header

    @staticmethod
    def generate_ip4_header(version, tos, len, id, flags, ttl, protocol, checksum, src_adr, dst_adr):
        return pack(IP_HEADER_FORMAT, version, tos, len, id, flags, ttl,
                    protocol, checksum, src_adr, dst_adr)

    @staticmethod
    def generate_tcp_header(dst_port, hdr_len=5, fin=0, syn=0, rst=0, psh=0,
                            ack=0, urg=0, window=5840, checksum=0, urg_ptr=0,
                            ack_seq=0, seq=12045, src_port=80):
        offset_res = (hdr_len << 4) + 0
        flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

        header = pack(TCP_HEADER_FORMAT,
                      src_port,
                      dst_port,
                      seq,
                      ack_seq,
                      offset_res,
                      flags,
                      window,
                      checksum,
                      urg_ptr)
        return header

    @staticmethod
    def generate_udp_header(dst_port, src_port=20, hdr_len=8, checksum=0):
        return pack(UDP_HEADER_FORMAT,
                    src_port,
                    dst_port,
                    hdr_len,
                    checksum)

    def generate_arp_header(self, dst_ip: str, htype=0x0001, ptype=0x0800, hlen=0x06, plen=0x04,
                            oper=0x01):
        local_ip = gethostbyname(gethostname())
        local_ip_arr = list(map(int, local_ip.split(".")))
        dst_ip_arr = list(map(int, dst_ip.split(".")))

        mac_header = self.generate_mac_header(src_mac="00:00:00:00:00:00",
                                              dst_mac="FF:FF:FF:FF:FF:FF",
                                              eth_type=[0x08, 0x06])

        header = pack("!HHBBH6B4B6B4B",
                      htype,
                      ptype,
                      hlen,
                      plen,
                      oper,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ARP sender MAC
                      local_ip_arr[0], local_ip_arr[1], local_ip_arr[2], local_ip_arr[3],  # ARP sender IP
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  # ARP target MAC
                      dst_ip_arr[0], dst_ip_arr[1], dst_ip_arr[2], dst_ip_arr[3])  # ARP target IP

        return mac_header + header

    @staticmethod
    def generate_icmp_header(type, code, checksum, rest):
        return pack(ICMP_HEADER_FORMAT, type, code, checksum, rest)

    @staticmethod
    def unpack_tcp_header(packet):
        packed_header = packet[20:40]
        header = unpack("!HHLLBBHHH", packed_header)
        return header

    @staticmethod
    def unpack_icmp_header(packet):
        packed_header = packet[20:28]
        header = unpack("!BBHL", packed_header)
        return header

    @staticmethod
    def unpack_arp_header(packet):
        packed_header = packet[14:42]
        header = unpack("!HHBBH6B4B6B4B", packed_header)
        return header

    @staticmethod
    def unpack_eth_header(packet):
        packed_header = packet[0:14]
        header = unpack("6B6B2B", packed_header)
        return header

    def _calculate_checksum(self):
        return
