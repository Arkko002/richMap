from queue import Queue
from threading import Thread, Lock

from factories.socket_type import SocketType
from scanner_socket import ScannerSocket


class ThreadedScannerSocket(ScannerSocket):
    def __init__(self, socket_type: SocketType):
        super().__init__(socket_type)

        self.lock = Lock()
        self.thread_queue = Queue()

    def start_probe_threads(self, packet, target, ports, timeout=None):
        for i in range(ports[0], ports[1] + 1):
            probe_thread = Thread(None, self.send_probe_packet(packet, target, i, timeout))
            probe_thread.daemon = True
            self.thread_queue.put(probe_thread)
            probe_thread.run()

        self.thread_queue.join()

    # TODO Remove this code duplication
    def thread_safe_send_probe_packet(self, packet, target, port, timeout=None):
        if timeout is None:
            timeout = self.default_soc_timeout

        self.soc.settimeout(timeout)
        self.icmp_soc.settimeout(timeout)

        for i in range(3):
            self.soc.sendto(packet, (target, port))

            tcp_result = self._await_response(self.soc)
            icmp_result = self._await_response(self.icmp_soc)

            if tcp_result is not None:
                self.lock.acquire()
                self.packet_dict[port] = tcp_result
                self.lock.release()

            if icmp_result is not None:
                self.lock.acquire()
                self.packet_dict[port] = icmp_result
                self.lock.release()