from port_scanning.banner_grabber.ftp_grabber import FTPGrabber
from port_scanning.banner_grabber.http_grabber import HTTPGrabber
from port_scanning.banner_grabber.ssh_grabber import SSHGrabber


class BannerGrabberFactory:
    @staticmethod
    def get_grabber(target, port):
        grabber_switcher = {
            21: FTPGrabber,
            22: SSHGrabber,
            80: HTTPGrabber
        }

        return grabber_switcher[port](target)
