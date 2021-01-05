from abc import ABC, abstractmethod


class AbstractBannerGrabber(ABC):
    """Defines common operations used by banner grabbing techniques"""
    def __init__(self, target):
        self.target = target

    @abstractmethod
    def get_banner(self):
        pass
