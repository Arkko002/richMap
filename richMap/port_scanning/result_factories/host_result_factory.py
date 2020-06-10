from richMap.port_scanning.model.host_result import HostResult
from richMap.port_scanning.model.scan_types import ScanTypes
from richMap.port_scanning.result_factories.abstract_host_result_factory import AbstractHostResultFactory


class HostResultFactory(AbstractHostResultFactory):
    def get_host_result(self, target_ip, scan_type: ScanTypes, **kwargs):
        return HostResult(target_ip, scan_type)
