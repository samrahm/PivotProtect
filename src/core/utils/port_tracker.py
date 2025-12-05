class PortTracker:
    def __init__(self):
        self.port_count = {}  # DS: HashMap

    def record_port(self, port):
        if port not in self.port_count:
            self.port_count[port] = 0
        self.port_count[port] += 1

    def is_suspicious(self, port, threshold=100):
        return self.port_count.get(port, 0) > threshold
