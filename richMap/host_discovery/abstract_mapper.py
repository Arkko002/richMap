from abc import ABC, abstractmethod


class NetmapperAbstract(ABC):

    @abstractmethod
    def scan_network(self):
        pass
