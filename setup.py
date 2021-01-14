from setuptools import setup, find_packages

setup(
    name="RichMap",
    version="0.1",
    py_modules=["rich_map"],
    packages=find_packages(exclude=("test",)),
    install_requires=[
        "Click",
        "Scapy"
    ],
    entry_points={
        "console_scripts": [
            "scan = rich_map:port_scan",
            "discover = rich_map:host_discovery"
        ]
    }
)
