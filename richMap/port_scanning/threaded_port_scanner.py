import concurrent.futures
from asyncio import Future

from port_scanning.model.host_result import HostResult
from port_scanning.port_scanner import PortScanner


# Socket Multithreading is bugged, doesnt recognize packet streams
class ThreadedPortScanner(PortScanner):
    """Variant of PortScanner that uses multithreading to increase performance of port scanning."""
    def __init__(self, target, scan, port_range):
        """

        :param target: IP of the targeted host
        :param scan: Type of the scan to be performed
        :param port_range: Range of ports to be scanned
        """
        super().__init__(target, scan, port_range)

    def perform_scan(self) -> HostResult:
        """
        Starts scanning the ports with attributes provided on class initialization.

        :return: HostResult which contains a list of PortResults
        """
        futures = self._start_threads()
        self.host_result.port_results = [f.result() for f in futures]
        return self.host_result

    def _start_threads(self) -> list[Future]:
        """
        Starts a thread for each port in the port range and performs a scan on it.

        :return: List of Futures
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(self.host_result.scan.get_scan_result,
                                       self.target, port, None) for port in range(self.host_result.port_range[1] + 1)]

        return futures
