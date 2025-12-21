"""
Simple Classifier Model for PivotProtect
Standalone module so pickle can find the class.
"""

import numpy as np


class SimpleClassifier:
    """Simple threshold-based classifier for intrusion detection"""
    
    def __init__(self):
        self.n_features_in_ = None
        self.thresholds = None
        
    def fit(self, X, y):
        """Train the classifier"""
        self.n_features_in_ = X.shape[1]
        # Calculate simple thresholds based on training data
        # Feature 0: connection rate, Feature 1: unique ports, Feature 2: avg size
        self.thresholds = {
            'connection_rate': np.percentile(X[y == 0, 0], 95),  # 95th percentile of normal
            'unique_ports': np.percentile(X[y == 0, 1], 95),
            'avg_size': np.percentile(X[y == 0, 2], 5),  # 5th percentile (small packets suspicious)
        }
        return self
    
    def predict(self, X):
        """Predict if traffic is normal (0) or attack (1)"""
        # Convert to numpy array if it's a list
        if isinstance(X, list):
            X = np.array(X)
        
        if len(X.shape) == 1:
            X = X.reshape(1, -1)
        
        predictions = []
        for features in X:
            # Simple rule based on available features
            # Features from detection_engine: [packet_size, packet_count_ip, flow_bytes, unique_ports, time_delta]
            try:
                # Extract what we need, with safe indexing
                packet_size = float(features[0]) if len(features) > 0 else 0
                packet_count = float(features[1]) if len(features) > 1 else 0
                flow_bytes = float(features[2]) if len(features) > 2 else 0
                unique_ports = float(features[3]) if len(features) > 3 else 0
                time_delta = float(features[4]) if len(features) > 4 else 0
                
                # Detection logic:
                # - High unique ports = port scan
                # - High packet count = potential DDoS
                # - Small packets repeatedly = suspicious
                is_attack = False
                
                if unique_ports > 5:  # Many unique ports = port scan
                    is_attack = True
                elif packet_count > 100:  # Very high packet count
                    is_attack = True
                elif packet_size < 100 and packet_count > 20:  # Many small packets
                    is_attack = True
                
                predictions.append(1 if is_attack else 0)
                
            except (ValueError, IndexError, TypeError):
                # If anything goes wrong, default to normal
                predictions.append(0)
        
        return np.array(predictions)
    
    def predict_proba(self, X):
        """Predict probability of each class"""
        pred = self.predict(X)
        # Simple probability: 0.9 for predicted class, 0.1 for other
        proba = np.zeros((len(pred), 2))
        for i, p in enumerate(pred):
            if p == 1:
                proba[i] = [0.1, 0.9]  # [P(normal), P(attack)]
            else:
                proba[i] = [0.9, 0.1]
        return proba
