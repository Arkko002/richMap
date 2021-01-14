import click

from richMap.console_view import ConsoleView
from richMap.exceptions.invalid_ip import InvalidIPError
from richMap.host_discovery.scans.host_discovery_scan_factory import HostDiscoveryScanFactory
from richMap.host_discovery.viewmodel.network_discovery_vm import NetworkDiscoveryViewModel
from richMap.port_scanning.scans.port_scan_factory import PortScanFactory
from richMap.host_discovery.host_discoverer import HostDiscoverer
from richMap.port_scanning.port_scanner import PortScanner
from richMap.port_scanning.viewmodel.host_result_vm import HostResultViewModel


@click.command()
@click.option("--map", required=True,
              type=click.Choice(["A", "F", "I", "N", "P", "S", "X"]),
              help="Discovery method to be used")
@click.option("--target", required=True, type=str, help="IP of targeted network")
@click.option("--verbosity", default=0, required=False, type=int)
def host_discovery(target, scan, verbosity):
    host_discovery_factory = HostDiscoveryScanFactory()
    scan_obj = host_discovery_factory.get_scanner(scan)

    mapper = HostDiscoverer(target, scan_obj)
    console_view = ConsoleView(verbosity)

    try:
        results = mapper.map_network()
    except PermissionError:
        console_view.print_error("Root privileges required for the selected discovery method.")
        return
    except InvalidIPError:
        console_view.print_error(f"{target} is not a valid IP address.")
        return

    results_vm = NetworkDiscoveryViewModel(results)
    console_view.print_results(results_vm)


@click.command()
@click.option("--ports", default="1-1024", type=str,
              help="Range of scanned ports separated with \"-\"")
@click.option("--scan", required=True,
              type=click.Choice(["T", "A", "F", "M", "N", "X", "W"]),
              help="Scan method to be used")
@click.option("--target", required=True, type=str, help="IP of targeted host")
@click.option("--verbosity", default=0, required=False, type=int)
def port_scan(target, ports, scan, verbosity):
    scanner_factory = PortScanFactory()
    scan_obj = scanner_factory.get_scanner(scan, )

    scanner = PortScanner(target, scan_obj, ports)
    console_view = ConsoleView(verbosity)

    try:
        results = scanner.perform_scan()
    except PermissionError:
        console_view.print_error("Root privileges required for the selected scan method.")
        return
    except InvalidIPError:
        console_view.print_error(f"{target} is not a valid IP address.")
        return

    results_vm = HostResultViewModel(results)
    console_view.print_results(results_vm)


