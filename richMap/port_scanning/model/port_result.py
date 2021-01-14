from richMap.port_scanning.model.port_state import PortState


class PortResult:
    """Contains information about probing of a specific port at the targeted host"""
    def __init__(self, port, port_state: PortState, result_positive: bool):
        """

        :param port: Targeted port
        :param port_state: Result of the probe represented as PortState
        :param result_positive: Whether the port can be considered accessible
        """
        self.port = port
        self.port_state = port_state
        self.result_positive = result_positive
