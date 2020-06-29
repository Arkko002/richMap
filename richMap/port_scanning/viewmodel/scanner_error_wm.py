from richMap.port_scanning.error_handling.scanner_error import ScannerError


class ScannerErrorViewModel():
    def __init__(self, scanner_error: ScannerError):
        self.error_str = self._convert_error_to_str(scanner_error)

    @staticmethod
    def _convert_error_to_str(scanner_error):
        error_switcher = {
            ScannerError.NoError: "",
            ScannerError.ConnectionTimeout: "Connection Timed Out"
        }

        return error_switcher[scanner_error]