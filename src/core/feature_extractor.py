'''
data structures used for feature extraction: 
dictionary
deque
'''

# extracting features acfcording to the preprocessing

from collections import defaultdict, deque
import time

class FeatureExtractor:
    def __init__(self):
        # DSA Structures
        self.packet_count_per_ip = defaultdict(int)
        self.bytes_per_flow = defaultdict(int)
        self.unique_ports_per_ip = defaultdict(set)
        self.time_window = deque(maxlen=1000)

        self.last_timestamp = None

    # EXTRACT NETWORK FEARURES
    def extract_from_packet(self, packet):
        """
        packet expected fields:
        - src_ip
        - dst_ip
        - dst_port
        - protocol
        - size
        - timestamp
        """

        # default timestamp if first packet
        now = packet["timestamp"]
        if self.last_timestamp is None:
            self.last_timestamp = now

        # basic features
        features = {
            "packet_size": packet["size"],
            "protocol": packet["protocol"],
            "src_ip": packet["src_ip"],
            "dst_ip": packet["dst_ip"],
        }

        # time delta
        time_delta = now - self.last_timestamp
        self.last_timestamp = now
        features["time_delta"] = time_delta

        # update counters
        self.packet_count_per_ip[packet["src_ip"]] += 1
        self.bytes_per_flow[(packet["src_ip"], packet["dst_ip"])] += packet["size"]
        self.unique_ports_per_ip[packet["src_ip"]].add(packet["dst_port"])

        # store advanced features
        features["packet_count_ip"] = self.packet_count_per_ip[packet["src_ip"]]
        features["flow_bytes"] = self.bytes_per_flow[(packet["src_ip"], packet["dst_ip"])]
        features["unique_ports"] = len(self.unique_ports_per_ip[packet["src_ip"]])
        features["dst_port"] = packet["dst_port"]

        # add packet to time window
        self.time_window.append(now)
        features["packet_rate"] = len(self.time_window)

        return features

    # LOG FILE FEATURES
    def extract_from_log(self, log_entry):
        """
        extract simple log features:
        - failed login count
        - repeated IP access
        - URL frequency
        """

        ip = log_entry.ip
        status = log_entry.status
        path = log_entry.endpoint

        features = {}

        # failed login detection
        features["failed_login"] = 1 if status == 401 else 0

        # track repeated access
        self.packet_count_per_ip[ip] += 1
        features["access_count_ip"] = self.packet_count_per_ip[ip]

        # track URLs
        self.unique_ports_per_ip[ip].add(path)
        features["unique_paths"] = len(self.unique_ports_per_ip[ip])

        return features
