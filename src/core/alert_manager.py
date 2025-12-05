'''
data structures:
-deque
-list
-set
-dictionary

algorithm 
-deduplication
-alert creation
-priority sorting
'''

from collections import deque
from datetime import datetime

class AlertManager:
    def __init__(self, max_history=100):
        # DS: deque for efficient append/pop
        self.alert_history = deque(maxlen=max_history)

        # DS: list for alerts fetched in current cycle
        self.current_alerts = []

        # DS: set for deduplication (store recent alert signatures)
        self.alert_cache = set()

    #   ADD A NEW ALERT (CALLED BY DetectionEngine)
    def add_alert(self, alert_type, severity, detail, source_ip=None):
        """
        Alert is a dict → easy to use in GUI & logging.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")

        alert = {
            "type": alert_type,
            "severity": severity,
            "detail": detail,
            "ip": source_ip,
            "timestamp": timestamp
        }

        # Algorithm: deduplication for identical alerts
        signature = (alert_type, severity, detail, source_ip)
        if signature in self.alert_cache:
            return  # Skip duplicate alert within short interval

        self.alert_cache.add(signature)

        # Store alert
        self.alert_history.append(alert)
        self.current_alerts.append(alert)

    #    GET ALERTS FOR GUI (ONE CYCLE)
    def get_new_alerts(self):
        """
        Returns alerts since last fetch.
        Then resets the buffer (but history remains).
        """
        alerts = self.current_alerts.copy()
        self.current_alerts.clear()
        return alerts

    #    GET FULL HISTORY (FOR DASHBOARD VIEW)
    def get_history(self):
        return list(self.alert_history)

    #    PRIORITY SORT (CRITICAL FIRST)
    def get_sorted_alerts(self):
        """
        Algorithm: severity priority ranking.
        """
        severity_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}

        return sorted(
            self.alert_history,
            key=lambda x: severity_rank.get(x["severity"], 0),
            reverse=True
        )
