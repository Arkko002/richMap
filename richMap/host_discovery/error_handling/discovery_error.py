from enum import Enum


class DiscoveryError(Enum):
    NoError = 0,
    ConnectionTimedOut = 1