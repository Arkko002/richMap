from enum import Enum


class MappingTypes(Enum):
    PingScan = 0
    ArpScan = 1
    IcmpScan = 2
    SynScan = 3
