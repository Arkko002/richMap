# TODO
from host_discovery.error_handling.discovery_error import DiscoveryError


class DiscoveryErrorViewModel:
    def __init__(self, error: DiscoveryError):
        self.error_wm = self._convert_error_to_wm(error)

    @staticmethod
    def _convert_error_to_wm(error):
        error_switcher = {
            DiscoveryError.NoError: "",
            DiscoveryError.ConnectionTimedOut: "Connection Timed Out"
        }

        return error_switcher[error]
