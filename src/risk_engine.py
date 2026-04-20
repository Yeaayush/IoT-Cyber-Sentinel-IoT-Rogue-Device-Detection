import numpy as np

class RiskEngine:
    def __init__(self):
        pass

    def calculate_risk_score(self, anomaly_scores):
        """
        Converts Isolation Forest decision function scores to a 0-100 risk score.
        
        Args:
            anomaly_scores (np.array): Output from model.decision_function(X).
                                       Higher values = more normal.
                                       Lower values (negative) = more abnormal.
        
        Returns:
            np.array: Risk scores from 0 to 100.
        """
        # Invert logic: Lower decision score -> Higher Risk
        # Sigmoid function can squash values to 0-1, then scale to 0-100
        # We want negative scores to map to > 0.5 (high risk)
        # We want positive scores to map to < 0.5 (low risk)
        
        # Using a modified sigmoid: 1 / (1 + exp(scale * score))
        # Adjust scale to control sensitivity
        scale = 10  # Sensitivity factor
        risk_probs = 1 / (1 + np.exp(scale * anomaly_scores))
        
        # Scale to 0-100 and convert to int
        risk_scores = (risk_probs * 100).astype(int)
        return risk_scores

    def classify_device(self, risk_score):
        """
        Classifies device based on risk score.
        """
        if risk_score < 40:
            return "Normal"
        elif 40 <= risk_score <= 75:
            return "Suspicious"
        else:
            return "Rogue"

    def process_signals(self, scores):
        """
        Batch process scores to get risk and labels.
        """
        risks = self.calculate_risk_score(scores)
        labels = [self.classify_device(r) for r in risks]
        return risks, labels
