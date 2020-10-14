from abc import ABC, abstractmethod


class AbstractBannerGrabber(ABC):
    def __init__(self, target):
        self.target = target

    @abstractmethod
    def get_banner(self):
        pass
