import socket
from scapy.layers.http import http_request

from richMap.port_scanning.banner_grabber.abstract_banner_grabber import AbstractBannerGrabber


class HTTPGrabber(AbstractBannerGrabber):
    def __init__(self, target):
        super(HTTPGrabber, self).__init__(target)
        self.hostname = self._get_hostname()

    def get_banner(self):
        response = http_request(self.hostname)
        return response.server

    def _get_hostname(self):
        return socket.gethostbyaddr(self.target)[0]
