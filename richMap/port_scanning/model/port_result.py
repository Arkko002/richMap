from richMap.port_scanning.error_handling.scanner_error_type import ScannerErrorType
from richMap.port_scanning.model.port_state import PortState


class PortResult:
    def __init__(self, port, port_state: PortState, error_type: ScannerErrorType):
        self.port = port
        self.port_state = port_state
        self.error_type = error_type
