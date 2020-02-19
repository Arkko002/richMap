from tkinter import *
from tkinter import ttk

from richMap.gui_util.command_parser import CommandParser
from richMap.host_discovery.host_discovery_types import HostDiscoveryTypes
from richMap.host_discovery.network_discovery_result import NetworkDiscoveryResult
from richMap.port_scanning.host_result import HostResult
from richMap.port_scanning.scan_types import ScanTypes
from richMap.scan_factories.host_discovery_scan_factory import HostDiscoveryScanFactory
from richMap.scan_factories.port_scan_factory import PortScanFactory
from .port_scanning.port_scanner import PortScanner
from .host_discovery.net_mapper import Netmapper


class RichGUI(ttk.Frame):
    """Acts as a controller for the rest of GUI and port/net scanners"""

    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, padding=(10, 10), **kwargs)
        self.parent = parent
        self.grid(column=0, row=0)

        self.outputs_frame = OutputsFrame(self)
        self.inputs_frame = InputsFrame(self)
        self.hosts_frame = HostsFrame(self)
        self.inputs_frame.grid(column=0, row=0)
        self.hosts_frame.grid(column=0, row=1, sticky=(W, S, N))
        self.outputs_frame.grid(column=0, row=1, sticky=(E,))

    def perform_scan(self, target: str, commands: str):
        command_parser = CommandParser()
        commands_dict = parse_commands(commands)

        if "m" in commands_dict:
            host_discovery_factory = HostDiscoveryScanFactory()
            scan = host_discovery_factory.get_scanner(commands_dict["m"])
            discovery_type = HostDiscoveryTypes(commands_dict["m"])

            network_discovery_result = NetworkDiscoveryResult(target, discovery_type)

            mapper = Netmapper(network_ip=target,
                               host_discovery=scan,
                               network_result=network_discovery_result)
            self.outputs_frame.print_scan_result(mapper.map_network())

        if "-s" in commands:
            port_scan_factory = PortScanFactory()
            scan = port_scan_factory.get_scanner(commands_dict["s"])
            scan_type = ScanTypes(commands_dict["s"])

            host_result = HostResult(target, scan_type)

            scan = PortScanner(target=target,
                               port_range=commands_dict["r"],
                               scan=scan,
                               host_result=host_result)
            self.outputs_frame.print_scan_result(scan.perform_scan())

        self.hosts_frame.add_host(target)


class InputsFrame(ttk.Frame):
    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, **kwargs)
        self.parent = parent

        self.target_entry = ttk.Entry(self)
        self.target_label = Label(self, text="Target:")

        self.command_entry = Entry(self)
        self.command_label = Label(self, text="Command:")

        self.scan_type_combobox = ttk.Combobox(self, values=["Ping Scan", "ARP Scan", "ARP Stealth Scan", "TCP Scan",
                                                             "SYN Scan", "UDP Scan", "ACK Scan", "Xmas Scan",
                                                             "Null Scan", "FIN Scan", "Maimon's Scan", "Window Scan", ])

        self.scan_type_combobox.current(0)
        self.scan_type_combobox.bind(
            "<<ComboboxSelected>>", self.add_scan_to_cmd_entry)
        self.scan_type_label = Label(self, text="Scan Type:")

        self.scan_button = Button(self, text="Scan", command=lambda: self.parent.perform_scan(self.target_entry.get(),
                                                                                              self.command_entry.get()))

        self.verbosity_label = Label(self, text="Verbosity:")
        self.verbosity_combobox = ttk.Combobox(self, values=["Normal", "High"])
        self.verbosity_combobox.current(0)

        self.target_entry.grid(column=1, row=0)
        self.target_label.grid(column=0, row=0)
        self.scan_type_label.grid(column=2, row=0, padx=5)
        self.scan_type_combobox.grid(column=3, row=0)
        self.command_label.grid(column=0, row=1)
        self.command_entry.grid(
            column=1, row=1, columnspan=3, sticky=(E, W), pady=10)
        self.scan_button.grid(column=4, row=0, padx=10)
        self.verbosity_label.grid(column=4, row=1)
        self.verbosity_combobox.grid(column=5, row=1)

    def add_scan_to_cmd_entry(self):

        scan_types = {
            "Ping Scan": "-mP",
            "ARP Scan": "-mA",
            "ARP Stealth Scan": "-mAs",
            "TCP Scan": "-sT",
            "SYN Scan": "-sS",
            "UDP Scan": "-sU",
            "ACK Scan": "-sA",
            "Xmas Scan": "-sX",
            "Null Scan": "-sN",
            "FIN Scan": "-sF",
            "Window Scan": "-sW",
            "Maimon's Scan": "-sM"
        }

        self.command_entry.delete(0, END)
        self.command_entry.insert(
            END, scan_types[self.scan_type_combobox.get()])


class OutputsFrame(ttk.Frame):
    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, borderwidth=2,
                           relief="sunken", **kwargs)
        self.parent = parent
        self.output_textbox = Text(self)
        self.output_textbox.grid(column=0, row=0)

    def print_scan_result(self, results):
        self.output_textbox.delete("1.0", END)
        self.output_textbox.insert(END, "Output of " + self.parent.inputs_frame.scan_type_combobox.get() + " on " +
                                   self.parent.inputs_frame.target_entry.get() + "\n")

        if self.parent.inputs_frame.verbosity_combobox.get() == "High":
            for item in results:
                self.output_textbox.insert(END, item + "\n")
        else:
            for item in results:
                if "Open" in item or "Filtered" in item or "Unfiltered" in item or "Host Up" in item:
                    self.output_textbox.insert(END, item + "\n")

    def print_error(self, error):
        self.output_textbox.delete("1.0", END)
        self.output_textbox.insert(END, error)


class HostsFrame(ttk.Frame):
    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, **kwargs)
        self.parent = parent
        self.host_listbox = Listbox(self, width=19, height=23)
        self.host_listbox.grid(column=0, row=0, padx=10, sticky=(S, W))
        self.host_listbox.bind('<<ListboxSelect>>', self.set_host)

    def add_host(self, host: str):
        for item in self.host_listbox.get(0, END):
            if host == item:
                return
        self.host_listbox.insert(END, host)

    def set_host(self):
        self.parent.inputs_frame.target_entry.delete(0, END)
        self.parent.inputs_frame.target_entry.insert(
            0, self.host_listbox.get(self.host_listbox.curselection()[0]))


if __name__ == "__main__":
    root = Tk()
    app = RichGUI(root)
    root.mainloop()
