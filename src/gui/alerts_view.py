import tkinter as tk
from tkinter import ttk, messagebox

class AlertsView(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#ecf0f1")
        self.pack(expand=True, fill="both")

        tk.Label(self, text="Alerts View", font=("Arial", 16), bg="#ecf0f1").pack(pady=20)

        self.tree = ttk.Treeview(self, columns=("Time", "IP", "Event"), show="headings")
        self.tree.heading("Time", text="Time")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("Event", text="Event")
        self.tree.pack(expand=True, fill="both", padx=20, pady=10)

        # Insert dummy alert
        self.tree.insert("", "end", values=("12:00", "192.168.0.1", "Dummy Alert"))

        tk.Button(self, text="Refresh Alerts", command=self.refresh_alerts).pack(pady=10)

    def refresh_alerts(self):
        messagebox.showinfo("Info", "No new alerts (dummy)")
