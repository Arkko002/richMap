from setuptools import setup, find_packages

setup(
    name="RichMap",
    version="0.1",
    packages=find_packages(include=["richMap", "richMap.*"]),
    install_requires=[
        "Click",
        "Scapy"
    ],
    entry_points={
        "console_scripts": [
            "scan = richMap.rich_map:port_scan",
            "discover = richMap.rich_map:host_discovery"
        ]
    }
)
