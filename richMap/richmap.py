import argparse
import sys
import scanner
import ctypes, sys

def parse_args(argv=sys.argv[1:]):
    """Parses the command line arguments"""
    parser = argparse.ArgumentParser(description="My Python script.")
    parser.add_argument("-r", "--range", type=str, action="store",
                        dest="range", metavar="RNG", help="Port range separated with '-'.")
    parser.add_argument("-t", "--target", type=str, action="store",
                        dest="target", metavar="HST", help="IP of the target machine.")
    parser.add_argument("-s", "--scan", type=str, action="store",
                        dest="scan_type", metavar="SCN", help="The type of scan to be used.")    
    return parser.parse_args(argv)

if __name__ == "__main__":
    Arguments = parse_args()
    if Arguments.scan_type == "T":
        scanner.Scanner.tcp_scan(Arguments.target, Arguments.range)
    if Arguments.scan_type == "S":
        scanner.Scanner.syn_scan(Arguments.target, Arguments.range)
    if Arguments.scan_type == "U":
        scanner.Scanner.udp_scan(Arguments.target, Arguments.range)
