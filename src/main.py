import tkinter as tk
import threading
import time
import sys
import os

# Add current directory to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.gui import IDPSGUI

# Optional: For live capture, uncomment these
# from live_capture import start_live_capture

if __name__ == "__main__":
    # ------------------------
    # Create Tkinter Root
    # ------------------------
    root = tk.Tk()

    # ------------------------
    # Initialize GUI with Demo Mode
    # ------------------------
    # demo_mode=True: uses simulated packets for offline demo
    # demo_mode=False: live capture can be appended later
    gui_app = IDPSGUI(root, demo_mode=True)

    # ------------------------
    # OPTIONAL: Start Live Capture (replace demo packets)
    # ------------------------
    # threading.Thread(target=lambda: start_live_capture(gui_app), daemon=True).start()

    # ------------------------
    # Run Tkinter mainloop
    # ------------------------
    root.mainloop()

