from queue import Queue
import concurrent.futures

from port_scanning.port_scanner import PortScanner


class ThreadedPortScanner(PortScanner):
    def __init__(self, target, scan, port_range):
        super().__init__(target, scan, port_range)

    def perform_scan(self):
        futures = self._start_threads()
        self.host_result.port_results = [f.result() for f in futures]
        return self.host_result

    def _start_threads(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.host_result.scan.get_scan_result,
                                       self.host_result.target,
                                       [i for i in
                                        range(self.host_result.port_range[0], self.host_result.port_range[1] + 1)],
                                       None)]
        return futures
