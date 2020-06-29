from richMap.port_scanning.error_handling.scanner_error import ScannerError
from richMap.port_scanning.model.port_result import PortResult
from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.model.scan_types import ScanType


# TODO Filtering the results based on rules from each scan
from richMap.port_scanning.viewmodel.scanner_error_wm import ScannerErrorViewModel


class PortResultViewModel:
    def __init__(self, port_result: PortResult):
        self.port = port_result.port
        self.port_state = port_result.port_state
        self.port_state_str = self.__convert_port_state_to_str(port_result.port_state)

        self.error_wm = ScannerErrorViewModel(port_result.error)

    def __str__(self):
        return f"{self.port} - {self.port_state_str}  {self.error_wm.error_str}"

    @staticmethod
    def __convert_port_state_to_str(port_state: PortState):
        port_state_switcher = {
            PortState.Closed: "Closed",
            PortState.Open: "Open",
            PortState.Filtered: "Filtered",
            PortState.Unfiltered: "Unfiltered",
            PortState.OpenFiltered: "Open | Filtered"
        }

        return port_state_switcher[port_state]

