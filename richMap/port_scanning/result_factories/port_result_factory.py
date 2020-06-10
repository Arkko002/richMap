from richMap.port_scanning.error_handling.scanner_error import ScannerError
from richMap.port_scanning.model.port_result import PortResult
from richMap.port_scanning.model.port_state import PortState
from richMap.port_scanning.result_factories.abstract_port_result_factory import AbstractPortResultFactory


class PortResultFactory(AbstractPortResultFactory):
    def get_port_result(self, port, port_state: PortState, error: ScannerError):
        return PortResult(port, port_state, error)
