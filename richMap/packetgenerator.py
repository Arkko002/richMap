from struct import pack

class packetgenerator(object):
    """Generates the headers for raw packets"""

    def generate_tcp_packet(dst_port, hdr_len = 5, fin = 0, syn = 0, rst = 0, psh = 0,
                            ack = 0, urg = 0, window = 5840, checksum = 0, urg_ptr = 0,
                            ack_seq = 0, rsrvd = 0, seq = 0 ,src_port=80):
            offset_res = (hdr_len << 4) + 0
            flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

            header = pack("!HHLLBBHHH", src_port, dst_port, seq, ack_seq, offset_res, flags, window, checksum, urg_ptr)
            return header

    def generate_udp_packet(dst_port, src_port = 20, hdr_len = 8, checksum = 0):
            header = pack("!HHHH", src_port, dst_port, hdr_len, checksum)
            return header

    def _calculate_checksum():

        

