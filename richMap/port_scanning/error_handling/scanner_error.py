from enum import Enum


class ScannerError(Enum):
    NoError = 0
    ConnectionTimeout = 1
