from richMap.port_scanning.error_handling.scanner_error_type import ScannerErrorType
from richMap.port_scanning.model.port_result import PortResult
from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.model.scan_types import ScanTypes

# TODO Filtering the results based on rules from each scan
class PortResultViewModel:
    def __init__(self, port_result: PortResult, scan_type: ScanTypes):
        self.port = port_result.port
        self.scan_type = scan_type

        self.port_state = port_result.port_state
        self.port_state_str = self.__conver_port_state_to_str(port_result.port_state)

        self.error_type = self.__convert_error_type

    @staticmethod
    def __conver_port_state_to_str(port_state: PortState):
        port_state_switcher = {
            PortState.Closed: "Closed",
            PortState.Open: "Open",
            PortState.Filtered: "Filtered",
            PortState.Unfiltered: "Unfiltered",
            PortState.OpenFiltered: "Open | Filtered"
        }

        return port_state_switcher[port_state]

    @staticmethod
    def __convert_error_type(error_type: ScannerErrorType):
        error_type_switcher = {
            ScannerErrorType.NoError: "No error",
            ScannerErrorType.ConnectionTimeout: "Connection timed out"
        }

        return error_type_switcher[error_type]
