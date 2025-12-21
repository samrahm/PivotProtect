'''
data structures used:
deque
hashmaps (dictionary)
'''

from collections import defaultdict, deque
import sys
import os

# Add core directory to path for utils imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.port_tracker import PortTracker
from utils.rate_limiter import RateLimiter

class DetectionEngine:
    def __init__(self, ml_model=None):
        # Hash maps for counting behavior patterns
        self.packet_count_per_ip = defaultdict(int)
        self.ports_per_ip = defaultdict(set)
        self.failed_logins = defaultdict(int)

        # Queue for DoS sliding-window rate detection
        self.time_window = deque(maxlen=500)

        # ML model (loaded separately)
        self.ml_model = ml_model

        # Collect alerts
        self.alerts = []

        # Thresholds (simple rule-based )
        self.PORT_SCAN_THRESHOLD = 15
        self.DOS_RATE_THRESHOLD = 300
        self.FAILED_LOGIN_THRESHOLD = 5

        self.port_tracker = PortTracker()    
        self.rate_limiter = RateLimiter()    

    #   MAIN ENTRY POINT FOR PACKET FEATURES
    def analyze_packet_features(self, f):
        """
        f = feature dictionary produced by FeatureExtractor
        Contains:
        - packet_size
        - time_delta
        - src_ip, dst_ip
        - packet_count_ip
        - flow_bytes
        - unique_ports
        - packet_rate
        """

        ip = f["src_ip"]
        port = f["dst_port"]

        # Update tracking
        self.packet_count_per_ip[ip] = f["packet_count_ip"]
        self.ports_per_ip[ip] = self.ports_per_ip[ip]  # already updated in FeatureExtractor

        # Port Tracker Usage
        self.port_tracker.record_port(port)
        if self.port_tracker.is_suspicious(port, threshold=15):
            self.alerts.append({
                "type": "PORT_SCAN",
                "ip": ip,
                "severity": "high",
                "detail": f"Unusual port access: {port}"
            })

        # Rate Limiter Usage
        self.rate_limiter.record_request(ip)
        if self.rate_limiter.is_rate_limited(ip):
            self.alerts.append({
                "type": "DOS_ATTACK",
                "ip": ip,
                "severity": "critical",
                "detail": "High request rate detected"
            })

        # RULE 1: PORT SCAN DETECTION 
        if f["unique_ports"] >= self.PORT_SCAN_THRESHOLD:
            self.alerts.append({
                "type": "PORT_SCAN",
                "ip": ip,
                "severity": "high",
                "detail": f"Unusual port access count: {f['unique_ports']}"
            })

        # RULE 2: DoS DETECTION (packet rate)
        self.time_window.append(f["time_delta"])
        current_rate = len(self.time_window)

        if current_rate >= self.DOS_RATE_THRESHOLD:
            self.alerts.append({
                "type": "DOS_ATTACK",
                "ip": ip,
                "severity": "critical",
                "detail": f"High packet rate: {current_rate}"
            })

        # RULE 3: FLOW ANOMALY USING PACKET SIZE
        if f["packet_size"] > 1500:  # oversized packet
            self.alerts.append({
                "type": "SUSPICIOUS_PACKET",
                "ip": ip,
                "severity": "medium",
                "detail": f"Large packet size: {f['packet_size']}"
            })

        # OPTIONAL ML DETECTION 
        if self.ml_model is not None:
            prediction = self.ml_model.predict([[
                f["packet_size"],
                f["packet_count_ip"],
                f["flow_bytes"],
                f["unique_ports"],
                f["time_delta"]
            ]])
            
            # Debug: Show ML is working
            print(f"[ML] Analyzed {ip}: unique_ports={f['unique_ports']}, packet_count={f['packet_count_ip']}, prediction={prediction[0]}")
            
            if prediction[0] == 1:
                self.alerts.append({
                    "type": "ML_ANOMALY",
                    "ip": ip,
                    "severity": "high",
                    "detail": "Machine learning model flagged anomaly"
                })
                print(f"[ML] ⚠️  ANOMALY DETECTED from {ip}")

        return self.alerts

    # LOG-BASED DETECTION
    def analyze_log_features(self, f):
        """
        f contains:
        - failed_login
        - access_count_ip
        - unique_paths
        """

        ip = f["ip"]
        self.failed_logins[ip] += f["failed_login"]

        # RULE: BRUTE FORCE DETECTION
        if self.failed_logins[ip] >= self.FAILED_LOGIN_THRESHOLD:
            self.alerts.append({
                "type": "BRUTE_FORCE",
                "ip": ip,
                "severity": "high",
                "detail": f"Failed login attempts: {self.failed_logins[ip]}"
            })

        return self.alerts

    #   GET ALERTS (GUI WILL CALL THIS)
    def get_alerts(self):
        latest = self.alerts.copy()
        self.alerts.clear()
        return latest
