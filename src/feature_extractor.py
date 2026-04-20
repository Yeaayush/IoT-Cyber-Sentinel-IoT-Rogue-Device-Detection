import pandas as pd
from sklearn.preprocessing import StandardScaler
import numpy as np

class FeatureExtractor:
    def __init__(self):
        self.scaler = StandardScaler()
        # Features commonly found in IoT network traffic datasets (CIC-IoT, UNSW-NB15)
        self.numeric_features = [
            'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
            'total_length_fwd_packets', 'total_length_bwd_packets',
            'flow_bytes_s', 'flow_packets_s', 'iat_mean', 'iat_std',
            'iat_max', 'iat_min'
        ]
        self.is_fitted = False

    def fit(self, df):
        """Fits the scaler on the training data."""
        # Select only relevant numeric features if they exist, else use what's available
        features = [f for f in self.numeric_features if f in df.columns]
        if not features:
            # Fallback for generic datasets, use all numeric columns
            features = df.select_dtypes(include=[np.number]).columns.tolist()
            self.numeric_features = features
        
        self.scaler.fit(df[features])
        self.is_fitted = True
        return self

    def transform(self, df):
        """Transforms the data using the fitted scaler."""
        if not self.is_fitted:
            raise ValueError("FeatureExtractor has not been fitted yet.")
        
        features = [f for f in self.numeric_features if f in df.columns]
        if not features:
             features = df.select_dtypes(include=[np.number]).columns.tolist()
             
        X = df[features].copy()
        X_scaled = self.scaler.transform(X)
        return pd.DataFrame(X_scaled, columns=features, index=df.index)

    def fit_transform(self, df):
        """Fits and transforms the data."""
        self.fit(df)
        return self.transform(df)
