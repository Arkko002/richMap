from richMap.port_scanning.model.scan_types import ScanType


class HostResult:
    def __init__(self, target_ip, scan_type: ScanType):
        self.target_ip = target_ip
        self.scan_type = scan_type
        self.port_results = []
