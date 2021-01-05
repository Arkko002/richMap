import click

from console_view import ConsoleView
from factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from factories.port_scan_factory import PortScanFactory
from host_discovery.host_discoverer import HostDiscoverer
from port_scanning.port_scanner import PortScanner
from port_scanning.threaded_port_scanner import ThreadedPortScanner
from port_scanning.viewmodel.host_result_vm import HostResultViewModel


@click.command()
@click.option("--map", required=True,
              type=click.Choice(["A", "F", "I", "N", "P", "S", "X"]),
              help="Discovery method to be used")
@click.option("--target", required=True, type=str, help="IP of targeted network")
@click.option("--verbosity", default=0, required=False, type=int)
def host_discovery(target, scan):
    host_discovery_factory = HostDiscoveryScanFactory()
    scan_obj = host_discovery_factory.get_scanner(scan)

    mapper = HostDiscoverer(target, scan_obj)
    return mapper.map_network()


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

    results = scanner.perform_scan()
    results_vm = HostResultViewModel(results)
    console_view.print_results(results_vm)


