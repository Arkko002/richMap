import click

from factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from factories.port_scan_factory import PortScanFactory
from host_discovery.host_discoverer import HostDiscoverer
from port_scanning.port_scanner import PortScanner


@click.group()
@click.option("--target", required=True, type=str, help="IP of targeted host / network")
@click.option("--verbosity", required=False, type=int)
@click.pass_context
def cli(ctx, target, verbosity):
    ctx.obj["TARGET"] = target
    ctx.obj["VERBOSITY"] = verbosity


@cli.command()
@click.option("--map", required=True,
              type=click.Choice(["mA", "mF", "mI", "mN", "mP", "mS", "mX"]),
              help="Discovery method to be used")
@click.pass_context
def host_discovery(ctx, scan):
    host_discovery_factory = HostDiscoveryScanFactory()
    scan_obj = host_discovery_factory.get_scanner(scan)

    mapper = HostDiscoverer(ctx.obj["TARGET"], scan_obj)
    return mapper.map_network()


@cli.command()
@click.option("--ports", default="0-1023",
              type=click.IntRange(0, 65535, clamp=True),
              help="Range of scanned ports separated with \"-\"")
@click.option("--scan", required=True,
              type=click.Choice(["sT", "sA", "sF", "sM", "sN", "sX", "sW"]),
              help="Scan method to be used")
@click.pass_context
def port_scan(ctx, ports, scan):
    scanner_factory = PortScanFactory()
    scan_obj = scanner_factory.get_scanner(scan)

    scanner = PortScanner(ctx.obj["TARGET"], scan_obj, ports)

    return scanner.perform_scan()
