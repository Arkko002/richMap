from richMap.port_scanning.error_handling.scanner_error import ScannerError
from richMap.port_scanning.model.port_state import PortState


class PortResult:
    def __init__(self, port, port_state: PortState, error: ScannerError):
        self.port = port
        self.port_state = port_state
        self.error = error
