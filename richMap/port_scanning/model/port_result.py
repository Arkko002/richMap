from richMap.port_scanning.error_handling.scanner_error_type import ScannerErrorType
from richMap.port_scanning.model.port_state import PortState


class PortResult:
    def __init__(self, port, port_state: PortState, **kwargs):
        self.port = port
        self.port_state = port_state

        if "error" in kwargs:
            self.error = kwargs.get("error")
