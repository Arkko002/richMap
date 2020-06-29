import re


def parse_commands(command_str: str):
    # Port range contains "-" so it requires individual extraction
    port_range_dict = {}
    if "-r" in command_str:
        port_range_re = re.search(r"-r \d+-\d+", command_str)
        port_range = port_range_re.group(0)

        # Remove the first hyphen from command
        port_range = port_range[1:]

        port_range_dict = dict(item for item in port_range.split(" "))

    command_list = command_str.split("-")
    command_list = [item.rstrip() for item in command_list if item]

    command_dict = dict(item.split(" ") for item in command_list)
    command_dict.update(port_range_dict)


class CommandParser:
    pass
