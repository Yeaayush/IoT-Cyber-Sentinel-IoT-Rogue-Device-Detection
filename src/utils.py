import pandas as pd
import numpy as np
import os
from datetime import datetime

def generate_synthetic_data(n_samples=1000, contamination=0.05, random_state=42):
    """
    Generates synthetic network traffic data mimicking IoT patterns.
    """
    np.random.seed(random_state)
    
    # Normal traffic (IoT devices usually have regular patterns)
    n_normal = int(n_samples * (1 - contamination))
    n_outliers = n_samples - n_normal
    
    # Generate Normal Data
    normal_data = {
        'flow_duration': np.random.exponential(scale=100, size=n_normal),
        'total_fwd_packets': np.random.poisson(lam=10, size=n_normal),
        'total_bwd_packets': np.random.poisson(lam=8, size=n_normal),
        'total_length_fwd_packets': np.random.normal(loc=500, scale=100, size=n_normal),
        'total_length_bwd_packets': np.random.normal(loc=800, scale=200, size=n_normal),
        'flow_bytes_s': np.random.normal(loc=1000, scale=200, size=n_normal),
        'flow_packets_s': np.random.normal(loc=10, scale=2, size=n_normal),
        'iat_mean': np.random.exponential(scale=50, size=n_normal),
        'iat_std': np.random.exponential(scale=10, size=n_normal),
        'iat_max': np.random.exponential(scale=100, size=n_normal),
        'iat_min': np.random.exponential(scale=1, size=n_normal)
    }
    
    # Generate Outlier/Rogue Data (DDoS, Scanning, etc.)
    outlier_data = {
        'flow_duration': np.random.exponential(scale=1000, size=n_outliers),
        'total_fwd_packets': np.random.poisson(lam=100, size=n_outliers),
        'total_bwd_packets': np.random.poisson(lam=100, size=n_outliers),
        'total_length_fwd_packets': np.random.normal(loc=5000, scale=1000, size=n_outliers),
        'total_length_bwd_packets': np.random.normal(loc=8000, scale=2000, size=n_outliers),
        'flow_bytes_s': np.random.normal(loc=10000, scale=2000, size=n_outliers),
        'flow_packets_s': np.random.normal(loc=100, scale=20, size=n_outliers),
        'iat_mean': np.random.exponential(scale=5, size=n_outliers),
        'iat_std': np.random.exponential(scale=50, size=n_outliers),
        'iat_max': np.random.exponential(scale=500, size=n_outliers),
        'iat_min': np.random.exponential(scale=0.1, size=n_outliers)
    }
    
    df_normal = pd.DataFrame(normal_data)
    df_outliers = pd.DataFrame(outlier_data)
    
    # Add dummy device IDs
    df_normal['device_id'] = [f'IoT_Dev_{np.random.randint(1, 50)}' for _ in range(n_normal)]
    df_outliers['device_id'] = [f'Unknown_Dev_{np.random.randint(50, 60)}' for _ in range(n_outliers)]
    
    # New Fields for UI
    device_types = ['Camera', 'Thermostat', 'SmartBulb', 'Hub', 'Speaker', 'Sensor']
    protocols = ['TCP', 'UDP', 'MQTT', 'HTTP', 'CoAP']
    
    # Assign random types/protocols
    df_normal['device_type'] = np.random.choice(device_types, n_normal)
    df_outliers['device_type'] = np.random.choice(['Unknown', 'RaspberryPi', 'Laptop'], n_outliers)
    
    df_normal['protocol'] = np.random.choice(protocols, n_normal, p=[0.3, 0.2, 0.3, 0.15, 0.05])
    df_outliers['protocol'] = np.random.choice(protocols, n_outliers) # Random distribution for outliers
    
    df_normal['dst_ip_count'] = np.random.randint(1, 5, n_normal)
    df_outliers['dst_ip_count'] = np.random.randint(5, 100, n_outliers) # High fan-out for scanners
    
    # Combine
    df = pd.concat([df_normal, df_outliers]).sample(frac=1).reset_index(drop=True)
    
    # Ensure no negative values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].abs()
    
    return df

def generate_security_report(history_df):
    """
    Generates a structured security report from the traffic history.
    """
    if history_df.empty:
        return "No data available for reporting."

    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_events = len(history_df)
    rogue_events = len(history_df[history_df['status'] == 'Rogue'])
    suspicious_events = len(history_df[history_df['status'] == 'Suspicious'])
    normal_events = len(history_df[history_df['status'] == 'Normal'])
    
    unique_devices = history_df['device_id'].nunique()
    rogue_devices = history_df[history_df['status'] == 'Rogue']['device_id'].unique().tolist()
    
    report_content = f"""# IoT Sentinel Security Report
Generated on: {report_time}

## Executive Summary
- **Total Network Events Analyzed**: {total_events}
- **Unique Devices Monitored**: {unique_devices}
- **Security Posture**: {"CRITICAL" if rogue_events > 0 else "SECURE"}

## Event Breakdown
- **Normal Traffic**: {normal_events} ({normal_events/total_events:.1%})
- **Suspicious Activity**: {suspicious_events} ({suspicious_events/total_events:.1%})
- **Confirmed Rogue Detections**: {rogue_events} ({rogue_events/total_events:.1%})

## Threat Analysis
"""
    if rogue_events > 0:
        report_content += "### Rogue Devices Identified:\n"
        for dev in rogue_devices:
            dev_data = history_df[history_df['device_id'] == dev].iloc[-1]
            report_content += f"- **{dev}**: Type: {dev_data['device_type']}, Protocol: {dev_data['protocol']}, Risk Score: {dev_data['risk_score']}\n"
    else:
        report_content += "No critical threats identified during this session.\n"

    report_content += f"""
## Top Suspicious Protocols
{history_df[history_df['status'] != 'Normal'].groupby('protocol')['risk_score'].mean().sort_values(ascending=False).to_string()}

---
*End of Report*
"""
    return report_content

def check_and_create_data():
    """Checks if data exists, otherwise generates it."""
    data_dir = 'data'
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        
    train_path = os.path.join(data_dir, 'train_data.csv')
    live_path = os.path.join(data_dir, 'live_traffic.csv')
    
    # Force regeneration if file exists but might be old/missing columns
    # For this exercise, we'll overwrite if called manually, or check if exists.
    # To ensure new columns are there, let's just overwrite live_traffic.
    
    if not os.path.exists(train_path):
        print("Generating training data...")
        df_train = generate_synthetic_data(n_samples=2000, contamination=0.01)
        df_train.to_csv(train_path, index=False)
        
    # Always regenerate live path to ensure new columns
    print("Generating live traffic data...")
    df_live = generate_synthetic_data(n_samples=500, contamination=0.15)
    df_live.to_csv(live_path, index=False)

if __name__ == "__main__":
    check_and_create_data()
