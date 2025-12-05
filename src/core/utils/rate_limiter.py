from collections import deque
import time

class RateLimiter:
    def __init__(self, window_size=60, limit=30):
        self.window_size = window_size
        self.limit = limit
        self.ip_windows = {}  # HashMap of Queues

    def record_request(self, ip):
        now = time.time()

        if ip not in self.ip_windows:
            self.ip_windows[ip] = deque()

        window = self.ip_windows[ip]
        window.append(now)

        while window and now - window[0] > self.window_size:
            window.popleft()

    def is_rate_limited(self, ip):
        return len(self.ip_windows.get(ip, [])) > self.limit
