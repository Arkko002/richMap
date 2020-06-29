from abc import ABC, abstractmethod


class AbstractPortResultFactory(ABC):
    @abstractmethod
    def get_port_result(self, port, port_state, error):
        pass
