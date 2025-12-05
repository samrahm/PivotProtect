import tkinter as tk
from tkinter import ttk
import sys
import os
import time
import threading

# Add parent directory (src) to path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.feature_extractor import FeatureExtractor
from core.detection_engine import DetectionEngine
from core.alert_manager import AlertManager
from core.ml_model_loader import MLModelLoader

class IDPSGUI:
    def __init__(self, root, demo_mode=False):
        self.root = root
        self.root.title("PivotProtect Dashboard")
        self.root.geometry("800x500")

        self.demo_mode = demo_mode

        # Initialize Core Engine
        self.feature_extractor = FeatureExtractor()
        ml_loader = MLModelLoader("models/ml_model.pkl")
        self.detection_engine = DetectionEngine(ml_model=ml_loader)
        self.alert_manager = AlertManager(max_history=200)

        # GUI Components
        dashboard_frame = tk.Frame(root)
        dashboard_frame.pack(side='top', fill='x', padx=10, pady=5)

        tk.Label(dashboard_frame, text="Packets Processed:").grid(row=0, column=0, sticky='w')
        self.packet_count_label = tk.Label(dashboard_frame, text="0")
        self.packet_count_label.grid(row=0, column=1, sticky='w')

        tk.Label(dashboard_frame, text="Unique IPs:").grid(row=1, column=0, sticky='w')
        self.unique_ip_label = tk.Label(dashboard_frame, text="0")
        self.unique_ip_label.grid(row=1, column=1, sticky='w')

        alerts_frame = tk.Frame(root)
        alerts_frame.pack(side='top', fill='both', expand=True, padx=10, pady=5)

        tk.Label(alerts_frame, text="Live Alerts").pack()
        self.alerts_tree = ttk.Treeview(alerts_frame, columns=("Time","Severity","Type","IP","Detail"), show='headings')
        self.alerts_tree.pack(fill='both', expand=True)

        for col in ("Time","Severity","Type","IP","Detail"):
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=120)

        # Packet queue (live or demo)
        self.live_packet_queue = []

        # If demo_mode → load simulated packets
        if self.demo_mode:
            self.load_demo_packets()

        # Start GUI refresh loop
        threading.Thread(target=self.refresh_loop, daemon=True).start()

    # DEMO PACKETS FOR OFFLINE MODE
    def load_demo_packets(self):
        import time
        self.live_packet_queue.extend([
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.1", "dst_port": 22,
             "protocol": "TCP", "size": 450, "timestamp": time.time()},
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.1", "dst_port": 23,
             "protocol": "TCP", "size": 460, "timestamp": time.time() + 0.5},
            {"src_ip": "192.168.1.5", "dst_ip": "10.0.0.1", "dst_port": 80,
             "protocol": "TCP", "size": 900, "timestamp": time.time() + 1.0},
        ])

    # CORE PROCESSING
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

    # UPDATE GUI VIEW
    def update_alerts_view(self):
        for row in self.alerts_tree.get_children():
            self.alerts_tree.delete(row)

        for a in self.alert_manager.get_history():
            self.alerts_tree.insert("", "end", values=(
                a["timestamp"], a["severity"], a["type"], a["ip"], a["detail"]
            ))

        self.packet_count_label.config(text=str(len(self.feature_extractor.time_window)))
        self.unique_ip_label.config(text=str(len(self.detection_engine.packet_count_per_ip)))

    # MAIN LOOP
    def refresh_loop(self):
        while True:
            # Process queued packets
            for packet in self.live_packet_queue:
                self.process_packet(packet)
            self.live_packet_queue.clear()

            # Refresh GUI
            self.update_alerts_view()
            time.sleep(0.5)
