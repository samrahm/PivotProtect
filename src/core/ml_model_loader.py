'''
data structures:
-dict  
-list 
-pickle

algo:
-loading 
-vector reshaping 
-prediction
'''

import pickle
import os

class MLModelLoader:
    def __init__(self, model_path):
        self.model = None
        self.metadata = {}

        if os.path.exists(model_path):
            self._load_model(model_path)
        else:
            print(f"[Warning] ML model not found at: {model_path}")

    # LOAD SERIALIZED MODEL
    def _load_model(self, path):
        """
        Uses:
        - Algorithm: File read → unpickle → load model.
        - DS: dict (metadata), stored model object.
        """
        with open(path, "rb") as f:
            self.model = pickle.load(f)

        # Store lightweight metadata
        self.metadata = {
            "model_name": type(self.model).__name__,
            "feature_count": getattr(self.model, "n_features_in_", None)
        }

        print(f"[INFO] Loaded ML model: {self.metadata['model_name']}")

    # PREDICT ON FEATURES
    def predict(self, feature_vector):
        """
        DS:
        - Wraps features into a list (ML expects 2D array)
        - Validates length using stored metadata.

        Algorithm:
        - Reshape → call model.predict() → return class label
        """

        if self.model is None:
            return [0]  # fallback: "normal"

        # Convert to required shape: [[f1, f2, f3 ...]]
        vector = [feature_vector]

        # Optional: feature-length safety check
        if self.metadata["feature_count"] is not None:
            if len(feature_vector) != self.metadata["feature_count"]:
                print("[WARN] Feature length mismatch with trained model.")

        return self.model.predict(vector)
