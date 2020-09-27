from port_scanning.model.port_state import PortState


class PortResult:
    def __init__(self, port, port_state: PortState, result_positive: bool):
        self.port = port
        self.port_state = port_state
        self.result_positive = result_positive
