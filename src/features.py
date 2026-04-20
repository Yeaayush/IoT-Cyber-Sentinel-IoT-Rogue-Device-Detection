import pandas as pd
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import joblib

class FeatureExtractor:
    def __init__(self):
        self.numeric_features = [
            'flow_duration', 'flow_byts_s', 'flow_pkts_s', 
            'tot_fwd_pkts', 'tot_bwd_pkts', 
            'totlen_fwd_pkts', 'totlen_bwd_pkts',
            'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'pkt_len_var'
        ]
        # In a real scenario, we might OHE ports or device types if known, 
        # but for unsupervised anomaly detection on unknown devices, 
        # relying heavily on flow stats is often more robust.
        # We will keep it simple for now and focus on numeric flow stats.
        
        self.pipeline = Pipeline([
            ('scaler', StandardScaler())
        ])
        
    def fit(self, df):
        """Fits the scaler to the data."""
        X = df[self.numeric_features]
        self.pipeline.fit(X)
        return self

    def transform(self, df):
        """Transforms data into feature vectors."""
        X = df[self.numeric_features]
        return self.pipeline.transform(X)
    
    def save(self, path="src/feature_pipeline.pkl"):
        joblib.dump(self.pipeline, path)
        
    def load(self, path="src/feature_pipeline.pkl"):
        self.pipeline = joblib.load(path)
        return self
