from richMap.port_scanning.model.port_result import PortResult
from richMap.port_scanning.model.port_state import PortState


# TODO Filtering the results based on rules from each scan
class PortResultViewModel:
    """Converts PortResult data into formatting suitable for display"""
    def __init__(self, port_result: PortResult):
        """

        :param port_result: Source PortResult object
        """
        self.port = port_result.port
        self.port_state = port_result.port_state
        self.port_state_str = self.__convert_port_state_to_str(port_result.port_state)
        self.result_positive = port_result.result_positive

    def __str__(self):
        return f"{self.port} - {self.port_state_str}"

    @staticmethod
    def __convert_port_state_to_str(port_state: PortState):
        port_state_switcher = {
            PortState.NoResponse: "No Response",
            PortState.Closed: "Closed",
            PortState.Open: "Open",
            PortState.Filtered: "Filtered",
            PortState.Unfiltered: "Unfiltered",
            PortState.OpenFiltered: "Open | Filtered"
        }

        return port_state_switcher[port_state]

