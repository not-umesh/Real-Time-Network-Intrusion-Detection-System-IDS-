"""
Render-Deployable IDS Dashboard
Standalone Streamlit dashboard that can run on Render free tier.
"""
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import deque
import time
import random
import os

# Page configuration
st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
    }
    .glass-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 20px;
        margin: 10px 0;
    }
    .metric-card {
        background: linear-gradient(135deg, rgba(102, 126, 234, 0.1) 0%, rgba(118, 75, 162, 0.1) 100%);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2.5rem;
        font-weight: bold;
        color: #00d4ff;
    }
    .metric-label {
        font-size: 0.9rem;
        color: #a0a0a0;
        text-transform: uppercase;
    }
    .alert-critical { background: linear-gradient(135deg, rgba(255, 0, 0, 0.2) 0%, rgba(139, 0, 0, 0.2) 100%); border-left: 4px solid #ff0000; }
    .alert-high { background: linear-gradient(135deg, rgba(255, 140, 0, 0.2) 0%, rgba(255, 100, 0, 0.2) 100%); border-left: 4px solid #ff8c00; }
    .alert-medium { background: linear-gradient(135deg, rgba(255, 215, 0, 0.2) 0%, rgba(255, 180, 0, 0.2) 100%); border-left: 4px solid #ffd700; }
    h1, h2, h3 { color: #ffffff !important; }
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.5; } 100% { opacity: 1; } }
    .pulse { animation: pulse 2s infinite; }
</style>
""", unsafe_allow_html=True)


class DemoDataGenerator:
    """Generates realistic demo data for the dashboard"""
    
    def __init__(self):
        self.attack_types = ["Port Scan", "DDoS", "Brute Force", "SQL Injection", "XSS", "Botnet"]
        self.severities = ["low", "medium", "high", "critical"]
        
    def generate_traffic_data(self, points: int = 60) -> pd.DataFrame:
        """Generate simulated traffic data"""
        now = datetime.now()
        timestamps = [now - timedelta(seconds=i) for i in range(points, 0, -1)]
        
        # Realistic traffic patterns
        base_packets = 500
        packets = [base_packets + random.randint(-100, 200) + 50 * np.sin(i/10) for i in range(points)]
        bytes_data = [p * random.randint(80, 150) for p in packets]
        threat_scores = [random.uniform(0.1, 0.4) for _ in range(points)]
        
        # Add some spikes
        for _ in range(3):
            spike_idx = random.randint(0, points-1)
            packets[spike_idx] *= 3
            threat_scores[spike_idx] = random.uniform(0.7, 0.95)
        
        return pd.DataFrame({
            'timestamp': timestamps,
            'packets': packets,
            'bytes': bytes_data,
            'threat_score': threat_scores
        })
    
    def generate_alerts(self, count: int = 5) -> list:
        """Generate sample alerts"""
        alerts = []
        for i in range(count):
            alerts.append({
                'timestamp': (datetime.now() - timedelta(minutes=i*5)).strftime('%H:%M:%S'),
                'attack_type': random.choice(self.attack_types),
                'severity': random.choice(self.severities),
                'source': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}:{random.randint(1024,65535)}",
                'target': f"192.168.1.{random.randint(1,255)}:{random.choice([22, 80, 443, 3306, 5432])}",
                'confidence': random.uniform(0.7, 0.99)
            })
        return alerts
    
    def get_stats(self) -> dict:
        """Generate current stats"""
        return {
            'packets_per_sec': random.randint(400, 800),
            'active_flows': random.randint(10, 50),
            'threats_today': random.randint(5, 25),
            'data_processed_mb': random.uniform(100, 500),
            'uptime_hours': random.randint(1, 48)
        }


# Initialize demo generator
demo = DemoDataGenerator()


def create_traffic_chart(df: pd.DataFrame) -> go.Figure:
    """Create traffic visualization"""
    fig = make_subplots(rows=2, cols=1, shared_xaxes=True, vertical_spacing=0.1,
                        subplot_titles=('Packets/sec', 'Bytes/sec'))
    
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['packets'], mode='lines',
                             fill='tozeroy', line=dict(color='#00d4ff', width=2),
                             fillcolor='rgba(0, 212, 255, 0.2)', name='Packets'), row=1, col=1)
    
    fig.add_trace(go.Scatter(x=df['timestamp'], y=df['bytes'], mode='lines',
                             fill='tozeroy', line=dict(color='#ff6b6b', width=2),
                             fillcolor='rgba(255, 107, 107, 0.2)', name='Bytes'), row=2, col=1)
    
    fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)',
                      plot_bgcolor='rgba(0,0,0,0)', height=400,
                      margin=dict(l=20, r=20, t=40, b=20), showlegend=False)
    return fig


def create_threat_gauge(level: float) -> go.Figure:
    """Create threat gauge"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=level * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Level", 'font': {'color': '#fff', 'size': 16}},
        number={'suffix': '%', 'font': {'color': '#fff', 'size': 24}},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': '#00d4ff'},
            'steps': [
                {'range': [0, 30], 'color': 'rgba(0,255,0,0.3)'},
                {'range': [30, 70], 'color': 'rgba(255,255,0,0.3)'},
                {'range': [70, 100], 'color': 'rgba(255,0,0,0.3)'}
            ]
        }
    ))
    fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', height=250)
    return fig


def create_attack_pie(alerts: list) -> go.Figure:
    """Create attack distribution"""
    attack_counts = {}
    for a in alerts:
        attack_counts[a['attack_type']] = attack_counts.get(a['attack_type'], 0) + 1
    
    fig = go.Figure(data=[go.Pie(
        labels=list(attack_counts.keys()), values=list(attack_counts.values()),
        hole=0.6, marker=dict(colors=['#ff6b6b', '#feca57', '#48dbfb', '#ff9ff3', '#54a0ff']),
        textinfo='percent+label', textfont=dict(color='#fff')
    )])
    fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', height=300,
                      showlegend=False, annotations=[dict(text='Attacks', x=0.5, y=0.5,
                                                          font=dict(size=16, color='#fff'), showarrow=False)])
    return fig


def render_metric(title: str, value: str, icon: str):
    st.markdown(f"""<div class="metric-card"><div style="font-size:2rem;">{icon}</div>
    <div class="metric-value">{value}</div><div class="metric-label">{title}</div></div>""", 
    unsafe_allow_html=True)


def render_alert(alert: dict):
    severity_class = f"alert-{alert['severity']}"
    st.markdown(f"""<div class="glass-card {severity_class}">
    <div style="display:flex;justify-content:space-between;"><strong style="color:#fff;">{alert['attack_type']}</strong>
    <span style="color:#aaa;">{alert['timestamp']}</span></div>
    <div style="margin-top:10px;color:#ccc;">📍 {alert['source']} → 🎯 {alert['target']}</div>
    <div style="color:#888;">Confidence: {alert['confidence']*100:.1f}%</div></div>""", unsafe_allow_html=True)


def main():
    # Header
    col1, col2 = st.columns([4, 1])
    with col1:
        st.markdown("""<h1>🛡️ Real-Time Network IDS <span class='pulse' style='color:#00ff00;font-size:0.5em;'>● LIVE</span></h1>""", 
                   unsafe_allow_html=True)
    with col2:
        st.caption(f"Updated: {datetime.now().strftime('%H:%M:%S')}")
    
    # Demo mode notice
    st.info("📊 **Demo Mode** - Showing simulated network traffic data. Deploy your own IDS for real monitoring!")
    
    # Get demo data
    stats = demo.get_stats()
    traffic_df = demo.generate_traffic_data()
    alerts = demo.generate_alerts(8)
    
    # Metrics
    cols = st.columns(5)
    metrics = [
        ("Packets/sec", f"{stats['packets_per_sec']}", "📦"),
        ("Active Flows", f"{stats['active_flows']}", "🔀"),
        ("Threats Today", f"{stats['threats_today']}", "⚠️"),
        ("Data Processed", f"{stats['data_processed_mb']:.1f} MB", "💾"),
        ("Uptime", f"{stats['uptime_hours']}h", "⏱️")
    ]
    for col, (title, value, icon) in zip(cols, metrics):
        with col:
            render_metric(title, value, icon)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Charts
    col1, col2 = st.columns([2, 1])
    with col1:
        st.markdown("### 📊 Network Traffic")
        st.plotly_chart(create_traffic_chart(traffic_df), use_container_width=True)
    with col2:
        st.markdown("### 🎯 Threat Level")
        avg_threat = np.mean(traffic_df['threat_score'])
        st.plotly_chart(create_threat_gauge(avg_threat), use_container_width=True)
    
    # Alerts and distribution
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### 🚨 Recent Alerts")
        for alert in alerts[:5]:
            render_alert(alert)
    with col2:
        st.markdown("### 📈 Attack Distribution")
        st.plotly_chart(create_attack_pie(alerts), use_container_width=True)
    
    # System Status
    st.markdown("### 💚 System Health")
    cols = st.columns(3)
    statuses = [("Packet Sniffer", "🟢 Demo Mode"), ("ML Model", "🟢 Loaded"), ("Telegram Alerts", "🟡 Configure")]
    for col, (name, status) in zip(cols, statuses):
        with col:
            st.markdown(f"""<div class="glass-card"><strong>{name}</strong><div style="font-size:1.5rem;">{status}</div></div>""", 
                       unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## ⚙️ Settings")
        st.selectbox("Network Interface", ["en0 (Demo)", "eth0", "wlan0"])
        st.slider("Anomaly Threshold", 0.0, 1.0, 0.5, 0.05)
        st.markdown("---")
        st.markdown("## 📖 About")
        st.markdown("""**Real-Time Network IDS**  
        Version 1.0.0
        
        [GitHub](https://github.com) | [Documentation](#)""")
    
    # Auto-refresh
    time.sleep(2)
    st.rerun()


if __name__ == "__main__":
    main()
