class TcpResponsePacket:
    def __init__(self, tcp_flags, tcp_header):
        self.tcp_flags = tcp_flags
        self.tcp_header = tcp_header

    def get_window_size(self):
        return self.tcp_header[6]
