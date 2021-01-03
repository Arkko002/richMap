import concurrent.futures

from scanner_socket.scanner_socket import ScannerSocket


class ThreadedScannerSocket(ScannerSocket):
    """A variant of ScannerSocket that uses multithreading to monitor for incoming TCP and ICMP packets"""
    def send_probe_packet(self, packet, target, port):
        """
        After sending a probe packet starts two threads that both listen for incoming result packets.
        One of the threads is for socket probe packet was sent with, the other for ICMP socket.

        :param packet: Probe packet to be sent
        :param target: IP of the targeted host
        :param port: Targeted port
        :return: Result packet on success, None on timeout
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            sockets = [self.icmp_soc, self.soc]
            self.soc.sendto(bytes(packet), (target, port))
            future_packets = {executor.submit(self._await_response(socket)): socket for socket in sockets}

            for future in concurrent.futures.as_completed(future_packets):
                try:
                    return future.result()
                # Socket will return None on timeout, which will cause TypeError when called with result()
                except TypeError:
                    return None
