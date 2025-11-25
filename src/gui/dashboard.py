import tkinter as tk
from tkinter import messagebox

class Dashboard(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#ecf0f1")
        self.pack(expand=True, fill="both")

        # Container frame to center vertically and horizontally
        container = tk.Frame(self, bg="#ecf0f1")
        container.place(relx=0.5, rely=0.5, anchor="center")  # Center in parent frame

        tk.Label(container, text="Pivot Protect", font=("Arial", 20), bg="#ecf0f1")\
            .pack(pady=10)
        tk.Label(container, text="AI-powered IDPS", font=("Arial", 16), bg="#ecf0f1")\
            .pack(pady=5)
        tk.Label(container, text="Dashboard", font=("Arial", 16), bg="#ecf0f1")\
            .pack(pady=20)
        tk.Button(container, text="Start Monitoring", command=self.start_monitoring, height=3, width= 15)\
            .pack(pady=10)

    def start_monitoring(self):
        messagebox.showinfo("Info", "Monitoring Started (dummy)")

