# gui_runner.py
import tkinter as tk
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gui.gui import IDPSGUI

root = tk.Tk()
app = IDPSGUI(root)
root.mainloop()
