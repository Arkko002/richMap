from richMap.abstract_error_handling.abstract_error import AbstractError


class DiscoveryError(AbstractError):
    def __init__(self, info_message):
        super().__init__(info_message)