from enum import Enum


class HostDiscoveryType(Enum):
    Ping = 0
    Arp = 1
    Icmp = 2
    Syn = 3
    Null = 4
    Xmas = 5
    Fin = 6
