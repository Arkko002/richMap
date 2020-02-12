from enum import Enum


class PortState(Enum):
    Closed = 0,
    Open = 1,
    Filtered = 2,
    Unfiltered = 3,
    OpenFiltered = 4

class PortResult:
    def __init__(self, port, port_state: PortState):
        self.port = port
        self.port_state = port_state
