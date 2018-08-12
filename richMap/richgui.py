from tkinter import *
from tkinter import ttk


class RichGUI(ttk.Frame):
    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, **kwargs)
        self.parent = parent


class Component(ttk.Frame):
    def __init__(self, parent, **kwargs):
        ttk.Frame.__init__(self, parent, **kwargs)
        self.parent = parent

if __name__ == "__main__":
    root = Tk()
    RichGUI(root).pack(side="top", fill="both", expand=True)
    root.mainloop()
