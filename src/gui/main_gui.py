import tkinter as tk
from dashboard import Dashboard
from alerts_view import AlertsView

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pivot Protect")
        self.geometry("850x450")

        # Sidebar
        sidebar = tk.Frame(self, width=150, bg="#2c3e50")
        sidebar.pack(side="left", fill="y")

        tk.Button(sidebar, text="Dashboard", command=self.show_dashboard, width=18).pack(pady=20)
        tk.Button(sidebar, text="Alerts View", command=self.show_alerts, width=18).pack(pady=10)

        # Content Frame
        self.content_frame = tk.Frame(self, bg="#ecf0f1")
        self.content_frame.pack(side="right", expand=True, fill="both")

        # Initialize with Dashboard
        self.dashboard = Dashboard(self.content_frame)
        self.alerts_view = AlertsView(self.content_frame)
        self.show_dashboard()

    def show_dashboard(self):
        self.alerts_view.pack_forget()
        self.dashboard.pack(expand=True, fill="both")

    def show_alerts(self):
        self.dashboard.pack_forget()
        self.alerts_view.pack(expand=True, fill="both")

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
