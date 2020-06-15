from enum import Enum


class PortState(Enum):
    Closed = 0,
    Open = 1,
    Filtered = 2,
    Unfiltered = 3,
    OpenFiltered = 4,
    NoResponse = 5

