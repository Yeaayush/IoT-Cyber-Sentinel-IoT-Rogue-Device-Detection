import streamlit as st
import pandas as pd
import time
import os
import plotly.express as px
import plotly.graph_objects as go
import sys

# Import local modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from feature_extractor import FeatureExtractor
from model import AnomalyDetector
from risk_engine import RiskEngine
from utils import check_and_create_data, generate_security_report

# --- Page Config ---
st.set_page_config(
    page_title="IoT Sentinel SOC Dashboard",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Theme & Custom CSS ---
st.markdown("""
<style>
    /* Hide Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}

    /* Professional Dark Theme */
    :root {
        --bg-primary: #0E1117;
        --bg-secondary: #161B22;
        --bg-card: #21262D;
        --text-main: #C9D1D9;
        --text-muted: #8B949E;
        --border-color: #30363D;
        --accent-blue: #58A6FF;
        --risk-low: #2EA043;
        --risk-medium: #D29922;
        --risk-high: #F85149;
        --risk-critical: #8E1542;
    }

    .stApp {
        background-color: var(--bg-primary);
        font-family: 'Inter', 'Segoe UI', Roboto, sans-serif;
        color: var(--text-main);
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: var(--bg-secondary) !important;
        border-right: 1px solid var(--border-color);
    }
    
    section[data-testid="stSidebar"] .stMarkdown, 
    section[data-testid="stSidebar"] .stRadio label {
        color: var(--text-main) !important;
    }

    /* Typography */
    h1, h2, h3, h4, h5, h6 {
        color: var(--text-main) !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em;
    }
    
    p, label, .stMarkdown {
        color: var(--text-main) !important;
    }

    /* SOC Card Styling */
    div[data-testid="metric-container"] {
        background-color: var(--bg-card);
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 1.25rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }
    
    div[data-testid="stMetricValue"] {
        color: var(--accent-blue) !important;
        font-family: 'JetBrains Mono', monospace;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
    }
    
    div[data-testid="stMetricLabel"] {
        color: var(--text-muted) !important;
        font-size: 0.9rem !important;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    /* Dataframe & Tables */
    div[data-testid="stDataFrame"] {
        border: 1px solid var(--border-color);
        border-radius: 6px;
        background-color: var(--bg-card);
    }

    /* Buttons */
    .stButton>button {
        background-color: var(--bg-card);
        color: var(--text-main);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 0.5rem 1rem;
        font-weight: 500;
        transition: all 0.2s ease;
    }
    
    .stButton>button:hover {
        border-color: var(--accent-blue);
        color: var(--accent-blue);
        background-color: rgba(88, 166, 255, 0.1);
    }
    
    .stButton>button[kind="primary"] {
        background-color: var(--risk-high);
        border-color: var(--risk-high);
        color: white;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
        border-bottom: 1px solid var(--border-color);
    }
    
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        border: none;
        color: var(--text-muted);
        padding: 10px 20px;
    }
    
    .stTabs [aria-selected="true"] {
        color: var(--accent-blue) !important;
        border-bottom: 2px solid var(--accent-blue) !important;
        background-color: transparent !important;
    }

    /* Risk Score Indicators */
    .risk-low { color: var(--risk-low); font-weight: bold; }
    .risk-medium { color: var(--risk-medium); font-weight: bold; }
    .risk-high { color: var(--risk-high); font-weight: bold; }
    .risk-critical { color: var(--risk-critical); font-weight: bold; }

</style>
""", unsafe_allow_html=True)

# --- Initialization ---
if 'history' not in st.session_state:
    # Initialize history with empty structure but correct columns including new ones
    st.session_state.history = pd.DataFrame(columns=[
        'timestamp', 'device_id', 'device_type', 'protocol', 
        'dst_ip_count', 'risk_score', 'status'
    ])
    st.session_state.last_avg_risk = 0

@st.cache_resource
def load_system():
    check_and_create_data()
    train_df = pd.read_csv('data/train_data.csv')
    extractor = FeatureExtractor()
    model = AnomalyDetector(contamination=0.02)
    risk_engine = RiskEngine()
    
    with st.spinner('Initializing Security Protocols...'):
        X_train = extractor.fit_transform(train_df)
        model.fit(X_train)
    
    return extractor, model, risk_engine

extractor, model, risk_engine = load_system()
live_data_source = pd.read_csv('data/live_traffic.csv')

# --- Helper Functions ---
def get_status_color(status):
    if status == 'Normal': return '#00FF9D'
    if status == 'Suspicious': return '#FFCC00'
    return '#FF2B2B'

# --- Navigation ---
with st.sidebar:
    # Top Section
    with st.container():
        st.title("IOT SENTINEL")
        st.caption("SECURITY OPERATIONS CENTER")
        st.markdown("---")

    # Middle Section
    with st.container():
        page_options = {
            "Dashboard": "Dashboard",
            "Device Inventory": "Device Monitoring",
            "Threat Alerts": "Rogue Alerts",
            "Security Analytics": "Analytics",
            "Security Reports": "Reports",
            "System Simulation": "Simulation"
        }
        selected_page_display = st.radio(
            "NAVIGATION", 
            list(page_options.keys()),
            label_visibility="collapsed"
        )
        page = page_options[selected_page_display]

    # Bottom Section
    with st.container():
        st.markdown("---")
        st.caption("SYSTEM STATUS: ONLINE")
        st.caption("SECURITY LEVEL: HIGH")

# --- Simulation Logic (Shared) ---
if 'run_simulation' not in st.session_state:
    st.session_state.run_simulation = False

# Use a fragment for the simulation logic to prevent full-page reloads
@st.fragment(run_every=1.0)
def run_simulation_fragment():
    if st.session_state.run_simulation:
        try:
            # Sample data
            batch = live_data_source.sample(n=1)
            
            # Feature Extraction & Inference
            X_batch = extractor.transform(batch)
            scores = model.decision_function(X_batch)
            risks, statuses = risk_engine.process_signals(scores)
            
            # Update Batch
            batch['risk_score'] = risks
            batch['status'] = statuses
            batch['timestamp'] = pd.Timestamp.now()
            
            # Ensure columns exist (handle old data vs new utils)
            if 'device_type' not in batch.columns: batch['device_type'] = 'Unknown'
            if 'protocol' not in batch.columns: batch['protocol'] = 'TCP'
            if 'dst_ip_count' not in batch.columns: batch['dst_ip_count'] = 0
            
            # Append to history
            new_record = batch[['timestamp', 'device_id', 'device_type', 'protocol', 'dst_ip_count', 'risk_score', 'status']]
            st.session_state.history = pd.concat([st.session_state.history, new_record], ignore_index=True).tail(1000)
            
        except Exception as e:
            st.error(f"Simulation Error: {e}")
            st.session_state.run_simulation = False

# Execute the simulation fragment
run_simulation_fragment()

# --- Page: Dashboard ---
if page == "Dashboard":
    st.title("SECURITY OVERVIEW")
    
    # Summary Metrics Row
    m1, m2, m3, m4 = st.columns(4)
    
    total_devices = st.session_state.history['device_id'].nunique()
    active_now = len(st.session_state.history[st.session_state.history['timestamp'] > pd.Timestamp.now() - pd.Timedelta(minutes=1)])
    rogues_detected = st.session_state.history[st.session_state.history['status'] == 'Rogue']['device_id'].nunique()
    avg_risk = st.session_state.history['risk_score'].mean() if not st.session_state.history.empty else 0
    
    m1.metric("ACTIVE DEVICES", active_now)
    m2.metric("TOTAL ASSETS", total_devices)
    m3.metric("THREATS DETECTED", rogues_detected)
    m4.metric("AVG RISK SCORE", f"{avg_risk:.1f}")
    
    st.markdown("---")
    
    # Main Grid
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.subheader("REAL-TIME THREAT MONITOR")
        if not st.session_state.history.empty:
            # Threat trend line chart
            trend_data = st.session_state.history.tail(100)
            fig_trend = go.Figure()
            
            # Add risk score line
            fig_trend.add_trace(go.Scatter(
                x=trend_data['timestamp'], 
                y=trend_data['risk_score'],
                mode='lines',
                name='Risk Score',
                line=dict(color='#58A6FF', width=2),
                fill='tozeroy',
                fillcolor='rgba(88, 166, 255, 0.1)'
            ))
            
            fig_trend.update_layout(
                template='plotly_dark',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=20, b=0),
                height=400,
                xaxis=dict(showgrid=False),
                yaxis=dict(gridcolor='#30363D', title="RISK SCORE"),
                showlegend=False
            )
            st.plotly_chart(fig_trend, use_container_width=True)
        else:
            st.info("Awaiting telemetry stream...")

    with col_right:
        st.subheader("RISK DISTRIBUTION")
        if not st.session_state.history.empty:
            # Donut chart for status distribution
            latest_status = st.session_state.history.sort_values('timestamp').groupby('device_id').last()['status'].value_counts()
            
            fig_donut = go.Figure(data=[go.Pie(
                labels=latest_status.index, 
                values=latest_status.values, 
                hole=.6,
                marker=dict(colors=['#2EA043', '#D29922', '#F85149'])
            )])
            
            fig_donut.update_layout(
                template='plotly_dark',
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=0, r=0, t=0, b=0),
                height=400,
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.1, xanchor="center", x=0.5)
            )
            st.plotly_chart(fig_donut, use_container_width=True)
        else:
            st.info("No active assets.")

    # Bottom Section: Activity Log
    st.subheader("RECENT SECURITY EVENTS")
    if not st.session_state.history.empty:
        log_df = st.session_state.history.tail(10).sort_values('timestamp', ascending=False)
        st.dataframe(
            log_df[['timestamp', 'device_id', 'device_type', 'risk_score', 'status']],
            column_config={
                "timestamp": st.column_config.DatetimeColumn("TIME", format="HH:mm:ss"),
                "device_id": "ASSET ID",
                "risk_score": st.column_config.NumberColumn("RISK", format="%d"),
                "status": "STATE"
            },
            use_container_width=True,
            hide_index=True
        )

# --- Page: Device Monitoring ---
elif page == "Device Monitoring":
    st.title("ASSET INVENTORY")
    
    # Filters
    f1, f2, f3 = st.columns([2, 1, 1])
    search = f1.text_input("SEARCH ASSET ID", placeholder="Enter Device ID...")
    filter_status = f2.multiselect("FILTER BY STATUS", ["Normal", "Suspicious", "Rogue"], default=["Normal", "Suspicious", "Rogue"])
    
    if not st.session_state.history.empty:
        latest_state = st.session_state.history.sort_values('timestamp').groupby('device_id').last().reset_index()
        
        if search:
            latest_state = latest_state[latest_state['device_id'].str.contains(search, case=False)]
        if filter_status:
            latest_state = latest_state[latest_state['status'].isin(filter_status)]
            
        st.dataframe(
            latest_state[['device_id', 'device_type', 'protocol', 'dst_ip_count', 'risk_score', 'status']],
            column_config={
                "risk_score": st.column_config.ProgressColumn("RISK LEVEL", min_value=0, max_value=100, format="%d"),
                "status": "SECURITY STATE",
                "dst_ip_count": "CONN COUNT"
            },
            use_container_width=True,
            hide_index=True
        )
        
        st.markdown("---")
        st.subheader("ASSET ADMINISTRATION")
        action_col1, action_col2, action_col3 = st.columns([2, 1, 1])
        with action_col1:
            selected_device = st.selectbox("SELECT TARGET ASSET", latest_state['device_id'].tolist())
        with action_col2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("INVESTIGATE", use_container_width=True):
                st.info(f"INITIATING FORENSIC ANALYSIS FOR {selected_device}...")
        with action_col3:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("ISOLATE ASSET", type="primary", use_container_width=True):
                st.error(f"ASSET {selected_device} QUARANTINED.")
    else:
        st.warning("NO ASSET DATA DETECTED.")

# --- Page: Rogue Alerts ---
elif page == "Rogue Alerts":
    st.title("THREAT INTELLIGENCE ALERTS")
    
    if not st.session_state.history.empty:
        rogues = st.session_state.history[st.session_state.history['status'] == 'Rogue'].sort_values('timestamp', ascending=False)
        
        if not rogues.empty:
            for i, row in rogues.head(10).iterrows():
                risk_val = row['risk_score']
                risk_label = "CRITICAL" if risk_val > 90 else "HIGH"
                
                with st.expander(f"[{risk_label}] THREAT DETECTED: {row['device_id']} | {row['timestamp'].strftime('%H:%M:%S')}", expanded=True):
                    c1, c2, c3 = st.columns(3)
                    c1.metric("RISK SCORE", f"{risk_val:.1f}")
                    c2.metric("PROTOCOL", row['protocol'])
                    c3.error("ACTION: IMMEDIATE QUARANTINE")
                    st.text(f"DEVICE TYPE: {row['device_type']} | DESTINATION COUNT: {row['dst_ip_count']}")
        else:
            st.success("NO ACTIVE THREATS DETECTED. ALL SYSTEMS SECURE.")
    else:
        st.info("SYSTEM INITIALIZING...")

# --- Page: Analytics ---
elif page == "Analytics":
    st.title("SECURITY ANALYTICS")
    
    if not st.session_state.history.empty:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("RISK DISTRIBUTION PROFILE")
            fig_hist = px.histogram(
                st.session_state.history, x="risk_score", nbins=20,
                color_discrete_sequence=['#58A6FF'],
                template='plotly_dark'
            )
            fig_hist.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis_title="RISK SCORE",
                yaxis_title="FREQUENCY"
            )
            st.plotly_chart(fig_hist, use_container_width=True)
            
        with col2:
            st.subheader("PROTOCOL VULNERABILITY ANALYSIS")
            proto_risk = st.session_state.history.groupby('protocol')['risk_score'].mean().reset_index()
            fig_proto = px.bar(
                proto_risk,
                x='protocol', y='risk_score',
                color='risk_score',
                color_continuous_scale=['#2EA043', '#D29922', '#F85149'],
                template='plotly_dark'
            )
            fig_proto.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                xaxis_title="PROTOCOL",
                yaxis_title="AVG RISK SCORE"
            )
            st.plotly_chart(fig_proto, use_container_width=True)
            
    else:
        st.info("INSUFFICIENT TELEMETRY FOR ANALYTICS.")

# --- Page: Reports ---
elif page == "Reports":
    st.title("SECURITY REPORTS")
    
    st.markdown("""
    Generate comprehensive security reports for compliance and forensic analysis. 
    Reports include executive summaries, threat breakdowns, and protocol analysis.
    """)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("GENERATE NEW REPORT")
        if not st.session_state.history.empty:
            if st.button("GENERATE SECURITY REPORT", use_container_width=True):
                report_md = generate_security_report(st.session_state.history)
                st.markdown("---")
                st.markdown(report_md)
                
                # Download button
                st.download_button(
                    label="DOWNLOAD REPORT (.MD)",
                    data=report_md,
                    file_name=f"IoT_Sentinel_Report_{pd.Timestamp.now().strftime('%Y%m%d_%H%M')}.md",
                    mime="text/markdown",
                    use_container_width=True
                )
        else:
            st.warning("NO DATA AVAILABLE. PLEASE START SIMULATION FIRST.")

    with col2:
        st.subheader("REPORTING INFO")
        st.info("""
        **Audit Scope:**
        - Device Inventory
        - Threat Alerts
        - Risk Scoring History
        - Protocol Anomalies
        """)

# --- Page: Simulation ---
elif page == "Simulation":
    st.title("SYSTEM SIMULATION CONTROL")
    
    c1, c2, c3 = st.columns(3)
    
    with c1:
        st.subheader("OPERATION CONTROLS")
        if st.button("START SIMULATION", type="primary" if not st.session_state.run_simulation else "secondary", use_container_width=True):
            st.session_state.run_simulation = True
            st.rerun()
            
        if st.button("PAUSE SIMULATION", use_container_width=True):
            st.session_state.run_simulation = False
            st.rerun()
            
        if st.button("RESET DATA", use_container_width=True):
            st.session_state.history = pd.DataFrame(columns=[
                'timestamp', 'device_id', 'device_type', 'protocol', 
                'dst_ip_count', 'risk_score', 'status'
            ])
            st.rerun()

    with c2:
        st.subheader("THREAT INJECTION")
        if st.button("INJECT ROGUE ASSET", use_container_width=True):
            rogue_entry = {
                'timestamp': pd.Timestamp.now(),
                'device_id': f"ROGUE_{pd.Timestamp.now().strftime('%S')}",
                'device_type': 'MALICIOUS_ACTOR',
                'protocol': 'TCP',
                'dst_ip_count': 999,
                'risk_score': 95.5,
                'status': 'Rogue'
            }
            st.session_state.history = pd.concat([st.session_state.history, pd.DataFrame([rogue_entry])], ignore_index=True)
            st.toast("ROGUE ASSET INJECTED")

    with c3:
        st.subheader("ENGINE STATUS")
        state_color = "#2EA043" if st.session_state.run_simulation else "#D29922"
        state_text = "OPERATIONAL" if st.session_state.run_simulation else "STANDBY"
        st.markdown(f"### <span style='color:{state_color}'>{state_text}</span>", unsafe_allow_html=True)


# --- Final Auto-Refresh for Simulation ---
if st.session_state.run_simulation:
    st.rerun()
