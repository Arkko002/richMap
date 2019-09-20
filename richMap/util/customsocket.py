import socket


class CustomSocket(socket.socket):
    spoofed_properties = {}

    def __init__(self, family, type, proto, fileno=None, *args, **kwargs):
        for key, value in kwargs.items():
            self.spoofed_properties[key] = value

        super().__init__(family, type, proto, fileno)