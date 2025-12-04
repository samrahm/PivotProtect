import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class IDPSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pivot Protect")
        self.root.geometry("500x450")
        self.root.configure(bg="#f5f5f5")

        ttk.Label(root, text="Pivot Protect",
                  font=("Arial", 14, "bold")).pack(pady=10)
        ttk.Label(root, text="Intrusion Detection & Prevention System",
                  font=("Arial", 14, "bold")).pack(pady=10)

        # Mode Selection
        mode_frame = ttk.Frame(root)
        mode_frame.pack(pady=5)

        ttk.Label(mode_frame, text="Mode:").grid(row=0, column=0, padx=5)
        self.mode_var = tk.StringVar(value="Static")

        mode_menu = ttk.Combobox(
            mode_frame,
            textvariable=self.mode_var,
            values=["Static", "Live"],
            width=15,
            state="readonly"
        )
        mode_menu.grid(row=0, column=1)
        mode_menu.bind("<<ComboboxSelected>>", self.update_mode)

        # File picker frame
        self.file_frame = ttk.Frame(root)
        self.file_frame.pack(pady=5)

        self.file_label = ttk.Label(self.file_frame, text="No file selected")
        self.file_label.pack(side="left", padx=5)

        self.browse_btn = ttk.Button(self.file_frame, text="Browse",
                                     command=self.pick_file)
        self.browse_btn.pack(side="right", padx=5)

        # Buttons
        btn_frame = ttk.Frame(root)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Start Scan",
                   command=self.start_scan).grid(row=0, column=0, padx=10)

        ttk.Button(btn_frame, text="Stop",
                   command=self.stop_scan).grid(row=0, column=1, padx=10)

        # Status
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(root, text="Status:").pack()
        self.status_label = ttk.Label(root, textvariable=self.status_var,
                                      foreground="gray")
        self.status_label.pack()

        # Logs
        ttk.Label(root, text="Alerts / Logs:").pack(pady=5)
        self.log_box = tk.Text(root, height=12, width=55)
        self.log_box.pack()

    # Functions

    def update_mode(self, event=None):
        """Enable only in Static mode, grey out in Live."""
        if self.mode_var.get() == "Static":
            self.browse_btn.state(["!disabled"])  # enable
        else:
            self.browse_btn.state(["disabled"])   # disable (greyscale)

    def pick_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_label.config(text=file_path)

    def start_scan(self):
        mode = self.mode_var.get()
        self.status_var.set("Running...")
        self.status_label.config(foreground="green")

        if mode == "Static":
            self.log("Running static analysis...")
        else:
            self.log("Starting live packet capture...")

        self.show_alert("Suspicious activity detected on port 23")

    def stop_scan(self):
        self.status_var.set("Idle")
        self.status_label.config(foreground="gray")
        self.log("Scan stopped.")

    def show_alert(self, msg):
        messagebox.showwarning("Threat Detected", msg)
        self.log(f"[ALERT] {msg}")

    def log(self, text):
        self.log_box.insert(tk.END, text + "\n")
        self.log_box.see(tk.END)


# Run GUI 
if __name__ == "__main__":
    root = tk.Tk()
    app = IDPSGUI(root)
    root.mainloop()
