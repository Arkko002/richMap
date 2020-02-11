from random import randint
from socket import SOCK_RAW, AF_PACKET
from richMap.util.custom_socket import CustomSocket


class SocketBuilder(object):
    def __init__(self):
        self.soc_types = {
            'A': CustomSocket(AF_PACKET, SOCK_RAW, CustomSocket.htons(3)),
            'As': CustomSocket(AF_PACKET, SOCK_RAW, CustomSocket.htons(3),)
        }

        super().__init__()

    def build_socket(self, socket_type: str) -> CustomSocket:
        pass

    def __generate_spoofed_mac(self):
        # TODO Add randomized OUI

        spoofed_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % (randint(0, 255), randint(0, 255),
                                                         randint(0, 255), randint(0, 255),
                                                         randint(0, 255), randint(0, 255))

        return spoofed_mac
