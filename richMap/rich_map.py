import click

from factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from factories.port_scan_factory import PortScanFactory
from host_discovery.host_discoverer import HostDiscoverer
from port_scanning.port_scanner import PortScanner


@click.command()
@click.option("--map", required=True,
              type=click.Choice(["mA", "mF", "mI", "mN", "mP", "mS", "mX"]),
              help="Discovery method to be used")
@click.option("--target", required=True, type=str, help="IP of targeted network")
@click.option("--verbosity", required=False, type=int)
def host_discovery(target, scan):
    host_discovery_factory = HostDiscoveryScanFactory()
    scan_obj = host_discovery_factory.get_scanner(scan)

    mapper = HostDiscoverer(target, scan_obj)
    return mapper.map_network()


@click.command()
@click.option("--ports", default="0-1023",
              type=click.IntRange(0, 65535, clamp=True),
              help="Range of scanned ports separated with \"-\"")
@click.option("--scan", required=True,
              type=click.Choice(["sT", "sA", "sF", "sM", "sN", "sX", "sW"]),
              help="Scan method to be used")
@click.option("--target", required=True, type=str, help="IP of targeted host")
@click.option("--verbosity", required=False, type=int)
def port_scan(target, ports, scan):
    scanner_factory = PortScanFactory()
    scan_obj = scanner_factory.get_scanner(scan)

    scanner = PortScanner(target, scan_obj, ports)

    return scanner.perform_scan()
