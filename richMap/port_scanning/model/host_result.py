from richMap.port_scanning.model.scan_types import ScanTypes


class HostResult:
    def __init__(self, target_ip, scan_type: ScanTypes):
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_results = []

    def return_positive_port_results(self):
        positive_results = []
        for result in self.port_results:
            if result.port_open is True:
                positive_results.append(result)

        return positive_results
