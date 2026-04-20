from sklearn.ensemble import IsolationForest
import numpy as np
import joblib

class AnomalyDetector:
    def __init__(self, contamination=0.05, n_estimators=100, random_state=42):
        """
        Initializes the Isolation Forest model.
        
        Args:
            contamination (float): The amount of contamination of the data set, i.e. the proportion of outliers in the data set.
            n_estimators (int): The number of base estimators in the ensemble.
            random_state (int): Seed used by the random number generator.
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1  # Use all available cores
        )
        self.is_fitted = False

    def fit(self, X):
        """Fits the model on normal network traffic data."""
        self.model.fit(X)
        self.is_fitted = True
        return self

    def predict(self, X):
        """
        Predicts if a particular sample is an outlier or not.
        Returns -1 for outliers and 1 for inliers.
        """
        if not self.is_fitted:
            raise ValueError("Model has not been fitted yet.")
        return self.model.predict(X)

    def decision_function(self, X):
        """
        Average anomaly score of X of the base classifiers.
        The anomaly score of an input sample is computed as
        the mean anomaly score of the trees in the forest.
        
        The measure of normality of an observation given a tree algorithm.
        It is -1 for outliers and 1 for inliers.
        """
        if not self.is_fitted:
            raise ValueError("Model has not been fitted yet.")
        return self.model.decision_function(X)

    def score_samples(self, X):
        """
        Opposite of the anomaly score defined in the original paper.
        The lower, the more abnormal.
        """
        if not self.is_fitted:
            raise ValueError("Model has not been fitted yet.")
        return self.model.score_samples(X)

    def save_model(self, filepath):
        joblib.dump(self.model, filepath)

    def load_model(self, filepath):
        self.model = joblib.load(filepath)
        self.is_fitted = True
