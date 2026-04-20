import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
from .features import FeatureExtractor

class RogueDeviceDetector:
    def __init__(self, contamination=0.05):
        """
        contamination: Expected proportion of outliers in the dataset.
        """
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        self.feature_extractor = FeatureExtractor()
        
    def train(self, df):
        """
        Trains the Isolation Forest model.
        """
        print("Feature extraction...")
        self.feature_extractor.fit(df)
        X = self.feature_extractor.transform(df)
        
        print("Training Isolation Forest...")
        self.model.fit(X)
        print("Training complete.")
        
    def predict(self, df):
        """
        Returns anomaly labels (-1 for outlier, 1 for inlier) and anomaly scores.
        """
        X = self.feature_extractor.transform(df)
        predictions = self.model.predict(X)
        scores = self.model.decision_function(X) # Average anomaly score of X of the base classifiers.
        
        return predictions, scores

    def save_model(self, model_path="src/model.pkl", pipeline_path="src/feature_pipeline.pkl"):
        joblib.dump(self.model, model_path)
        self.feature_extractor.save(pipeline_path)
        
    def load_model(self, model_path="src/model.pkl", pipeline_path="src/feature_pipeline.pkl"):
        self.model = joblib.load(model_path)
        self.feature_extractor.load(pipeline_path)
