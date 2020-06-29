from richMap.port_scanning.error_handling.scanner_error import ScannerError
from richMap.port_scanning.model.port_state import PortState


class PortResult:
    def __init__(self, port, port_state: PortState, result_positive: bool, error: ScannerError):
        self.port = port
        self.port_state = port_state
        # Set to true if scan specific rules determine successful port probing
        self.result_positive = result_positive
        self.error = error
