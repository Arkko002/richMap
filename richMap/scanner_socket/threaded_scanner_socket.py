import concurrent.futures

from scanner_socket.scanner_socket import ScannerSocket


class ThreadedScannerSocket(ScannerSocket):
    def send_probe_packet(self, packet, target, port):

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
