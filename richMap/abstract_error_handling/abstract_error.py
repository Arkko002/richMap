from abc import ABC, abstractmethod


class AbstractError(ABC):
    def __init__(self, info_message):
        self.info_message = info_message