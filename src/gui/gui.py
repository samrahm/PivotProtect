import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import sys, os, time, threading

# Add src folder to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feature_extractor import FeatureExtractor
from core.detection_engine import DetectionEngine
from core.alert_manager import AlertManager
from core.ml_model_loader import MLModelLoader

# Optional live capture
try:
    from scapy.all import sniff, IP, TCP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class IDPSGUI:
    def __init__(self, root, demo_mode=False):
        self.root = root
        self.root.title("PivotProtect Dashboard")
        self.root.geometry("900x500")
        self.demo_mode = demo_mode

        # Core engine
        self.feature_extractor = FeatureExtractor()
        ml_loader = MLModelLoader("models/ml_model.pkl")
        self.detection_engine = DetectionEngine(ml_model=ml_loader)
        self.alert_manager = AlertManager(max_history=200)

        # Packet queue
        self.live_packet_queue = []

        # Menu
        menubar = tk.Menu(root)
        root.config(menu=menubar)
        mode_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Mode", menu=mode_menu)
        mode_menu.add_command(label="Live", command=self.start_live_mode)
        mode_menu.add_command(label="Static", command=self.start_static_mode)

        # Dashboard frame
        dashboard_frame = tk.Frame(root)
        dashboard_frame.pack(side='top', fill='x', padx=10, pady=5)

        tk.Label(dashboard_frame, text="Packets Processed:").grid(row=0, column=0, sticky='w')
        self.packet_count_label = tk.Label(dashboard_frame, text="0")
        self.packet_count_label.grid(row=0, column=1, sticky='w')

        tk.Label(dashboard_frame, text="Unique IPs:").grid(row=1, column=0, sticky='w')
        self.unique_ip_label = tk.Label(dashboard_frame, text="0")
        self.unique_ip_label.grid(row=1, column=1, sticky='w')

        # Alerts frame
        alerts_frame = tk.Frame(root)
        alerts_frame.pack(side='top', fill='both', expand=True, padx=10, pady=5)
        tk.Label(alerts_frame, text="Live Alerts").pack()
        self.alerts_tree = ttk.Treeview(alerts_frame,
            columns=("Time","Severity","Type","IP","Detail"), show='headings')
        self.alerts_tree.pack(fill='both', expand=True)
        for col in ("Time","Severity","Type","IP","Detail"):
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=120)

        # Load demo packets if requested
        if self.demo_mode:
            self.load_demo_packets()

        # Start GUI refresh loop
        threading.Thread(target=self.refresh_loop, daemon=True).start()

    # ---------------- Demo / Static ----------------
    def load_demo_packets(self):
        self.live_packet_queue.extend([
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.1", "dst_port": 22,
             "protocol": "TCP", "size": 450, "timestamp": time.time()},
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.1", "dst_port": 23,
             "protocol": "TCP", "size": 460, "timestamp": time.time() + 0.5},
        ])

    def start_static_mode(self):
        file_path = filedialog.askopenfilename(
            title="Select static packet file",
            filetypes=[("CSV files","*.csv"),("JSON files","*.json"),("All files","*.*")]
        )
        if not file_path:
            return
        import csv, json
        packets = []
        if file_path.endswith(".csv"):
            with open(file_path, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    packets.append({
                        "src_ip": row["src_ip"],
                        "dst_ip": row["dst_ip"],
                        "dst_port": int(row["dst_port"]),
                        "protocol": row["protocol"],
                        "size": int(row["size"]),
                        "timestamp": float(row["timestamp"])
                    })
        elif file_path.endswith(".json"):
            with open(file_path) as f:
                data = json.load(f)
                for row in data:
                    packets.append(row)
        else:
            messagebox.showerror("Error", "Unsupported file type")
            return

        self.live_packet_queue.extend(packets)
        messagebox.showinfo("Static Mode", f"Loaded {len(packets)} packets for static processing")

    # ---------------- Live capture ----------------
    def start_live_mode(self):
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy not installed, cannot run live capture")
            return

        def capture(packet):
            if packet.haslayer(IP) and packet.haslayer(TCP):
                pkt_dict = {
                    "src_ip": packet[IP].src,
                    "dst_ip": packet[IP].dst,
                    "dst_port": packet[TCP].dport,
                    "protocol": "TCP",
                    "size": len(packet),
                    "timestamp": packet.time
                }
                self.live_packet_queue.append(pkt_dict)

        threading.Thread(target=lambda: sniff(prn=capture, store=False), daemon=True).start()
        messagebox.showinfo("Live Mode", "Live capture started")

    # ---------------- Core processing ----------------
    def process_packet(self, packet):
        features = self.feature_extractor.extract_from_packet(packet)
        alerts = self.detection_engine.analyze_packet_features(features)
        for alert in alerts:
            self.alert_manager.add_alert(
                alert_type=alert["type"],
                severity=alert["severity"],
                detail=alert["detail"],
                source_ip=alert.get("ip")
            )

    def update_alerts_view(self):
        for row in self.alerts_tree.get_children():
            self.alerts_tree.delete(row)
        for a in self.alert_manager.get_history():
            self.alerts_tree.insert("", "end", values=(
                a["timestamp"], a["severity"], a["type"], a["ip"], a["detail"]
            ))
        self.packet_count_label.config(text=str(len(self.feature_extractor.time_window)))
        self.unique_ip_label.config(text=str(len(self.detection_engine.packet_count_per_ip)))

    def refresh_loop(self):
        while True:
            for packet in self.live_packet_queue:
                self.process_packet(packet)
            self.live_packet_queue.clear()
            self.update_alerts_view()
            time.sleep(0.5)


if __name__ == "__main__":
    root = tk.Tk()
    gui_app = IDPSGUI(root, demo_mode=True)
    root.mainloop()
