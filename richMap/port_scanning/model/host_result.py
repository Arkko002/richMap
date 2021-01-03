class HostResult:
    """Contains information about port scanning performed on targeted host"""
    def __init__(self, target, port_range, scan):
        """

        :param target: IP of the targeted host
        :param port_range: Port range to be scanned
        :param scan: Type of the scan to be performed
        """
        self.target = target
        self.port_range = [int(port) for port in port_range.split("-")]
        self.scan = scan
        self.port_results = []
