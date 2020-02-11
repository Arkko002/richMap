from struct import pack, unpack
from socket import gethostbyname, gethostname


class PacketGenerator(object):

    @staticmethod
    def generate_tcp_packet(dst_port, hdr_len=5, fin=0, syn=0, rst=0, psh=0,
                            ack=0, urg=0, window=5840, checksum=0, urg_ptr=0,
                            ack_seq=0, seq=12045, src_port=80):
            offset_res = (hdr_len << 4) + 0
            flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

            header = pack("!HHLLBBHHH", src_port, dst_port, seq, ack_seq, offset_res, flags, window, checksum, urg_ptr)
            return header

    @staticmethod
    def generate_udp_packet(dst_port, src_port=20, hdr_len=8, checksum=0):
            header = pack("!HHHH", src_port, dst_port, hdr_len, checksum)
            return header

    @staticmethod
    def generate_arp_packet(dst_ip: str, htype=0x0001, ptype=0x0800, hlen=0x06, plen=0x04,
                            oper=0x01):

        local_ip = gethostbyname(gethostname())
        local_ip_arr = local_ip.split(".")
        dst_ip_arr = dst_ip.split(".")

        header = pack("!6B6B2BHHBBH6B4B6B4B",
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  # Ethernet layer dest. MAC
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Eth. layer src. MAC
                      0x08, 0x06,  # ETH protocol (ARP)
                      htype,
                      ptype,
                      hlen,
                      plen,
                      oper,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # ARP sender MAC
                      int(local_ip_arr[0]), int(local_ip_arr[1]), int(local_ip_arr[2]), int(local_ip_arr[3]),  # ARP sender IP
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  # ARP target MAC
                      int(dst_ip_arr[0]), int(dst_ip_arr[1]), int(dst_ip_arr[2]), int(dst_ip_arr[3]))  # ARP target IP
        return header

    @staticmethod
    def generate_spoofed_eth_arp_packet(eth_src_mac, dst_ip: str, htype=0x0001, ptype=0x0800, hlen=0x06, plen=0x04,
                                        oper=0x01):
        local_ip = gethostbyname(gethostname())
        local_ip_arr = local_ip.split(".")
        dst_ip_arr = dst_ip.split(".")

        header = pack("!6B6B2BHHBBH6B4B6B4B",
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  # Ethernet layer dest. MAC
                      eth_src_mac[0], eth_src_mac[1], eth_src_mac[2], eth_src_mac[3], eth_src_mac[4], eth_src_mac[5],  # Eth. sender MAC
                      0x08, 0x06,  # ETH protocol (ARP)
                      htype,
                      ptype,
                      hlen,
                      plen,
                      oper,
                      eth_src_mac[0], eth_src_mac[1], eth_src_mac[2], eth_src_mac[3], eth_src_mac[4], eth_src_mac[5],  # ARP sender MAC
                      int(local_ip_arr[0]), int(local_ip_arr[1]), int(local_ip_arr[2]), int(local_ip_arr[3]),  # ARP sender IP)
                      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  # ARP target MAC
                      int(dst_ip_arr[0]), int(dst_ip_arr[1]), int(dst_ip_arr[2]), int(dst_ip_arr[3])  # ARP target IP)
                      )
        return header

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
