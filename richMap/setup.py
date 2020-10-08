from setuptools import setup

setup(
    name="RichMap",
    version="0.1",
    py_modules=["rich_map_click"],
    install_requires=[
        "Click",
    ],
    entry_points={
        "console_scripts": [
            "richmap = rich_map_click:cli"
        ]
    }
)
