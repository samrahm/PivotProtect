from static_analysis.dsa_structures import HashMap


class PortTracker:
    def __init__(self):
        self.port_count = HashMap()  # Custom HashMap implementation

    def record_port(self, port):
        self.port_count.increment(port)

    def is_suspicious(self, port, threshold=100):
        return (self.port_count.get(port) or 0) > threshold
