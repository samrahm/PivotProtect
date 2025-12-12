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
        
        # Pause flag
        self.is_paused = False

        # Menu
        menubar = tk.Menu(root)
        root.config(menu=menubar)
        mode_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Mode", menu=mode_menu)
        mode_menu.add_command(label="Live", command=self.start_live_mode)
        mode_menu.add_command(label="Static", command=self.start_static_mode)
        
        # Control menu
        control_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Control", menu=control_menu)
        control_menu.add_command(label="Pause", command=self.toggle_pause)
        control_menu.add_command(label="Clear Alerts", command=self.clear_alerts)

        # Dashboard frame
        dashboard_frame = tk.Frame(root)
        dashboard_frame.pack(side='top', fill='x', padx=10, pady=5)

        tk.Label(dashboard_frame, text="Packets Processed:").grid(row=0, column=0, sticky='w')
        self.packet_count_label = tk.Label(dashboard_frame, text="0")
        self.packet_count_label.grid(row=0, column=1, sticky='w')

        tk.Label(dashboard_frame, text="Unique IPs:").grid(row=1, column=0, sticky='w')
        self.unique_ip_label = tk.Label(dashboard_frame, text="0")
        self.unique_ip_label.grid(row=1, column=1, sticky='w')
        
        # Pause/Resume button
        self.pause_button = tk.Button(dashboard_frame, text="⏸ Pause", command=self.toggle_pause, 
                                       bg="orange", fg="white", padx=10)
        self.pause_button.grid(row=0, column=2, padx=10)
        
        # Clear alerts button
        self.clear_button = tk.Button(dashboard_frame, text="Clear", command=self.clear_alerts,
                                       bg="red", fg="white", padx=10)
        self.clear_button.grid(row=1, column=2, padx=10)
        
        # Status label
        self.status_label = tk.Label(dashboard_frame, text="Status: Running", fg="green")
        self.status_label.grid(row=0, column=3, padx=20)

        # Alerts frame with color mapping
        alerts_frame = tk.Frame(root)
        alerts_frame.pack(side='top', fill='both', expand=True, padx=10, pady=5)
        tk.Label(alerts_frame, text="Live Alerts (Color-coded by Severity)", font=("Arial", 10, "bold")).pack()
        
        # Create a frame for the treeview
        tree_frame = tk.Frame(alerts_frame)
        tree_frame.pack(fill='both', expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.alerts_tree = ttk.Treeview(tree_frame,
            columns=("●", "Time", "Severity", "Type", "IP", "Detail"), show='headings', yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.alerts_tree.yview)
        self.alerts_tree.pack(fill='both', expand=True)
        
        # Configure columns with indicator column
        self.alerts_tree.heading("●", text="")
        self.alerts_tree.column("●", width=20)
        
        for col in ("Time", "Severity", "Type", "IP", "Detail"):
            self.alerts_tree.heading(col, text=col)
            self.alerts_tree.column(col, width=100)
        
        # Configure tag colors for severity levels
        self.alerts_tree.tag_configure("critical", foreground="white", background="#d32f2f")  # Red
        self.alerts_tree.tag_configure("high", foreground="white", background="#f57c00")      # Orange
        self.alerts_tree.tag_configure("medium", foreground="white", background="#fbc02d")    # Yellow
        self.alerts_tree.tag_configure("low", foreground="black", background="#4caf50")       # Green

        # Bind selection to show origin details
        self.alerts_tree.bind("<<TreeviewSelect>>", self.on_alert_select)

        # Load demo packets if requested
        if self.demo_mode:
            self.load_demo_packets()

        # Start GUI refresh loop
        threading.Thread(target=self.refresh_loop, daemon=True).start()

    # ---------------- Control Methods ----------------
    def toggle_pause(self):
        """Toggle between pause and resume"""
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_button.config(text="▶ Resume", bg="green")
            self.status_label.config(text="Status: Paused", fg="red")
        else:
            self.pause_button.config(text="⏸ Pause", bg="orange")
            self.status_label.config(text="Status: Running", fg="green")
    
    def clear_alerts(self):
        """Clear all alerts from the display"""
        # Clear alert manager storage
        self.alert_manager.alert_history.clear()
        self.alert_manager.alert_cache.clear()
        self.alert_manager.current_alerts.clear()

        # Clear GUI tree view
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)

        # Clear live packet queue
        try:
            self.live_packet_queue.clear()
        except Exception:
            self.live_packet_queue = []

        # Reset feature extractor internal state
        try:
            fe = self.feature_extractor
            fe.packet_count_per_ip.clear()
            fe.bytes_per_flow.clear()
            fe.unique_ports_per_ip.clear()
            fe.time_window.clear()
            fe.last_timestamp = None
        except Exception:
            pass

        # Reset detection engine internal state
        try:
            de = self.detection_engine
            de.packet_count_per_ip.clear()
            de.ports_per_ip.clear()
            de.failed_logins.clear()
            de.time_window.clear()
            de.alerts.clear()
        except Exception:
            pass

        # Reset dashboard counters
        self.packet_count_label.config(text="0")
        self.unique_ip_label.config(text="0")

        # Ensure scanner is running (unpause) after clear
        self.is_paused = False
        self.pause_button.config(text="⏸ Pause", bg="orange")
        self.status_label.config(text="Status: Running", fg="green")

        messagebox.showinfo("Cleared", "All alerts cleared and scanner restarted")

    # ---------------- Demo / Static ----------------
    def load_demo_packets(self):
        self.live_packet_queue.extend([
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.1", "dst_port": 22,
             "protocol": "TCP", "size": 450, "timestamp": time.time()},
            {"src_ip": "192.168.1.2", "dst_ip": "10.0.0.1", "dst_port": 23,
             "protocol": "TCP", "size": 460, "timestamp": time.time() + 0.5},
            {"src_ip": "192.168.1.5", "dst_ip": "10.0.0.1", "dst_port": 80,
             "protocol": "TCP", "size": 900, "timestamp": time.time() + 1.0},
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
        
        # Color mapping for severity
        severity_colors = {
            "critical": ("critical", "🔴"),
            "high": ("high", "🟠"),
            "medium": ("medium", "🟡"),
            "low": ("low", "🟢")
        }
        
        for a in self.alert_manager.get_history():
            severity = a["severity"].lower()
            tag, indicator = severity_colors.get(severity, ("low", "⭕"))
            
            self.alerts_tree.insert("", "end", values=(
                indicator,
                a["timestamp"],
                a["severity"],
                a["type"],
                a["ip"],
                a["detail"]
            ), tags=(tag,))
        
        self.packet_count_label.config(text=str(len(self.feature_extractor.time_window)))
        self.unique_ip_label.config(text=str(len(self.detection_engine.packet_count_per_ip)))

    def on_alert_select(self, event):
        """Show details about where an alert originated from when clicked."""
        sel = self.alerts_tree.selection()
        if not sel:
            return
        item = sel[0]
        values = self.alerts_tree.item(item, "values")
        # values: (indicator, timestamp, severity, type, ip, detail)
        try:
            ip = values[4]
        except Exception:
            ip = None

        origin_lines = []
        origin_lines.append(f"Alert: {values[3]}\nSeverity: {values[2]}\nDetail: {values[5]}")

        if ip and ip != 'None':
            origin_lines.append(f"Source IP: {ip}")
            # Packet counts
            try:
                pc = self.detection_engine.packet_count_per_ip.get(ip, 0)
                origin_lines.append(f"Packets seen from IP: {pc}")
            except Exception:
                pass

            # Unique ports seen
            try:
                ports = None
                # Prefer detection_engine ports_per_ip, fallback to feature_extractor
                if hasattr(self.detection_engine, 'ports_per_ip'):
                    ports = list(self.detection_engine.ports_per_ip.get(ip, []))
                if not ports:
                    ports = list(self.feature_extractor.unique_ports_per_ip.get(ip, []))
                origin_lines.append(f"Observed ports: {ports}")
            except Exception:
                pass

            # Flow bytes summary (best-effort)
            try:
                flows = []
                for (s, d), b in self.feature_extractor.bytes_per_flow.items():
                    if s == ip:
                        flows.append(f"to {d}: {b} bytes")
                if flows:
                    origin_lines.append("Flow bytes:\n  " + "\n  ".join(flows))
            except Exception:
                pass

        messagebox.showinfo("Alert Origin", "\n\n".join(origin_lines))

    def refresh_loop(self):
        while True:
            # Only process packets if not paused
            if not self.is_paused:
                for packet in self.live_packet_queue:
                    self.process_packet(packet)
                self.live_packet_queue.clear()
            
            # Always update the display
            self.update_alerts_view()
            time.sleep(0.5)


if __name__ == "__main__":
    root = tk.Tk()
    gui_app = IDPSGUI(root, demo_mode=True)
    root.mainloop()
