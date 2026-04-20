# IoT Sentinel

A lightweight, agentless, real-time security system for IoT networks using Unsupervised Machine Learning (Isolation Forest).

## 🛡️ Project Overview

This project, **IoT Sentinel**, detects unauthorized (Rogue) or compromised IoT devices by analyzing network traffic flow data. It uses an **Isolation Forest** model to identify anomalous behavior patterns without requiring any software installation on the IoT devices themselves (Agentless).

### Key Features
- **Real-time Detection**: Analyzes network flows as they happen.
- **Agentless**: Works by passive network monitoring (CSV simulation provided).
- **Unsupervised Learning**: Detects unknown attacks (zero-day) and rogue devices without labeled training data.
- **Risk Scoring**: Assigns a risk score (0-100) to each device.
- **Interactive Dashboard**: Streamlit-based UI for monitoring and alerts.

## 📂 Project Structure

```
IoT_Sentinel/
├── data/                   # Generated synthetic datasets (train & live)
├── src/                    # Source code
│   ├── app.py              # Main Streamlit Dashboard application
│   ├── feature_extractor.py# Data preprocessing and scaling
│   ├── model.py            # Isolation Forest Model wrapper
│   ├── risk_engine.py      # Risk scoring and classification logic
│   └── utils.py            # Synthetic data generation helper
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

## 🚀 Setup and Run Instructions

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
The application includes a synthetic data generator that runs automatically on the first launch.
```bash
streamlit run src/app.py
```

### 3. Usage
- The dashboard will open in your browser (usually `http://localhost:8501`).
- The system will automatically train the model on the `train_data.csv` (normal traffic).
- Use the sidebar to **"Run Real-time Simulation"**.
- Adjust the **Simulation Speed** to see how the system reacts to incoming traffic.
- Watch the **Risk Meter** and **Rogue Device Table** for alerts.

## 🧠 Methodology

1. **Data Ingestion**: Network flow statistics (Duration, Packets/s, Bytes/s, Inter-arrival times) are ingested.
2. **Feature Extraction**: Data is standardized using `StandardScaler` to ensure the ML model treats all features equally.
3. **Anomaly Detection (Isolation Forest)**:
   - The model isolates observations by randomly selecting a feature and then randomly selecting a split value.
   - Anomalies are susceptible to isolation (shorter path lengths in the tree).
   - Normal points require more splits to be isolated.
4. **Risk Scoring**:
   - The raw anomaly score is converted to a probability using a sigmoid function.
   - **Normal (<40%)**: Standard IoT behavior.
   - **Suspicious (40-75%)**: Unusual spikes or timing.
   - **Rogue (>75%)**: High probability of attack or unauthorized device.

## 📊 Datasets
This project is designed to be compatible with:
- **CIC-IoT Dataset**
- **UNSW-NB15 Dataset**
*Note: For demonstration, `src/utils.py` generates synthetic data mimicking these feature sets.*
