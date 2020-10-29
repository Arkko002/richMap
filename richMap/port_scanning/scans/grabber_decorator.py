from port_scanning.banner_grabber.banner_grabber_factory import BannerGrabberFactory


def grabber_decorator(scan):
    def wrapper(*args, **kwargs):
        if kwargs["grab_banners"]:
            port_result = scan.get_scan_result(kwargs["target"], kwargs["port"], kwargs["timeout"])
            banner_grabber = BannerGrabberFactory().get_grabber(kwargs["target"], port_result.port)
            port_result.banner_result = banner_grabber.get_banner()
            return port_result

        return scan.get_scan_result(*args, **kwargs)
