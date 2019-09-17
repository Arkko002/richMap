from tkinter import *
from tkinter import ttk
from .port_scanning.portscanner import PortScanner
from .host_discovery.netmapper import Netmapper


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
        commands_list = commands.split(" ")

        range_str = None
        net_interface = None

        if "-m" or "-s" not in commands_list:
            self.outputs_frame.print_error(
                "You need to select the scan/map type")
            return

        for command in commands_list:
            if command.startswith("-m"):
                scan_type = command.replace("-m", "")
            elif command.startswith("-s"):
                scan_type = command.replace("-s", "")
            elif command.startswith("-r"):
                range_str = command.replace("-r", "")
            elif command.startswith("-i"):
                net_interface = command.replace("-i", "")

        if "-m" in commands:
            mapper = Netmapper(
                network_ip=target, scan_type=scan_type, net_interface=net_interface)
            self.outputs_frame.print_scan_result(mapper.map_network())

        if "-s" in commands:
            scan = PortScanner(
                target=target, scan_type=scan_type, port_range=range_str)
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

    def add_scan_to_cmd_entry(self, *args):

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

    def set_host(self, *args):
        self.parent.inputs_frame.target_entry.delete(0, END)
        self.parent.inputs_frame.target_entry.insert(
            0, self.host_listbox.get(self.host_listbox.curselection()[0]))


if __name__ == "__main__":
    root = Tk()
    app = RichGUI(root)
    root.mainloop()
