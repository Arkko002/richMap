class HostResult:
    def __init__(self, target, port_range, scan):
        self.target = target
        self.port_range = [int(port) for port in port_range.split("-")]
        self.scan = scan
        self.port_results = []
