import pandas as pd
import numpy as np
import random
import time

def generate_synthetic_data(num_samples=1000):
    """
    Generates synthetic network traffic data mimicking IoT device behavior.
    Includes normal traffic and some 'rogue' anomalies.
    """
    np.random.seed(42)
    
    # Device Types
    device_types = ['Thermostat', 'Camera', 'SmartBulb', 'SmartLock', 'Unknown_Device']
    
    data = []
    
    for _ in range(num_samples):
        device_id = f"IOT_{random.randint(100, 999)}"
        device_type = np.random.choice(device_types, p=[0.3, 0.3, 0.2, 0.1, 0.1])
        
        # Base stats for normal behavior
        if device_type == 'Thermostat':
            bytes_out = np.random.normal(100, 20)
            bytes_in = np.random.normal(500, 50)
            flow_duration = np.random.normal(0.5, 0.1)
            dest_port = 443
        elif device_type == 'Camera':
            bytes_out = np.random.normal(5000, 1000)
            bytes_in = np.random.normal(200, 20)
            flow_duration = np.random.normal(5.0, 1.0)
            dest_port = 8080
        elif device_type == 'SmartBulb':
            bytes_out = np.random.normal(50, 10)
            bytes_in = np.random.normal(50, 10)
            flow_duration = np.random.normal(0.2, 0.05)
            dest_port = 80
        elif device_type == 'SmartLock':
            bytes_out = np.random.normal(200, 20)
            bytes_in = np.random.normal(200, 20)
            flow_duration = np.random.normal(1.0, 0.2)
            dest_port = 8883 # MQTT
        else: # Unknown/Potential Rogue
            bytes_out = np.random.normal(1000, 500)
            bytes_in = np.random.normal(1000, 500)
            flow_duration = np.random.normal(2.0, 1.0)
            dest_port = np.random.choice([22, 23, 80, 443, 6667])

        # Inject Anomalies (Rogue Behavior)
        is_rogue = False
        if random.random() < 0.05: # 5% anomalies
            is_rogue = True
            bytes_out = bytes_out * np.random.uniform(5, 20) # Data exfiltration
            flow_duration = flow_duration * np.random.uniform(0.1, 10)
            dest_port = np.random.choice([22, 23]) # Telnet/SSH scanning
            
        # Feature Engineering (Mimicking CIC-IoT)
        record = {
            'timestamp': time.time(),
            'device_id': device_id,
            'device_type': device_type,
            'src_port': random.randint(49152, 65535),
            'dst_port': dest_port,
            'flow_duration': abs(flow_duration),
            'flow_byts_s': abs(bytes_out + bytes_in) / (abs(flow_duration) + 1e-5),
            'flow_pkts_s': np.random.randint(1, 100) / (abs(flow_duration) + 1e-5),
            'tot_fwd_pkts': int(abs(bytes_out / 100)) + 1,
            'tot_bwd_pkts': int(abs(bytes_in / 100)) + 1,
            'totlen_fwd_pkts': abs(bytes_out),
            'totlen_bwd_pkts': abs(bytes_in),
            'fwd_pkt_len_mean': abs(bytes_out) / (int(abs(bytes_out / 100)) + 1),
            'bwd_pkt_len_mean': abs(bytes_in) / (int(abs(bytes_in / 100)) + 1),
            'pkt_len_var': np.random.uniform(0, 100),
            # Label for evaluation only
            'label': 'Rogue' if is_rogue else 'Normal'
        }
        data.append(record)
        
    df = pd.DataFrame(data)
    return df

if __name__ == "__main__":
    print("Generating synthetic IoT network traffic data...")
    df = generate_synthetic_data(2000)
    df.to_csv("data/network_traffic.csv", index=False)
    print(f"Data saved to data/network_traffic.csv with {len(df)} records.")
