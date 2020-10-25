from enum import Enum


class PortState(Enum):
    NoResponse = 0,
    Closed = 1,
    Open = 2,
    Filtered = 3,
    Unfiltered = 4,
    OpenFiltered = 5,

