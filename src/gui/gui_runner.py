# gui_runner.py
import tkinter as tk
from gui.gui import IDPSGUI

root = tk.Tk()
app = IDPSGUI(root)
root.mainloop()
