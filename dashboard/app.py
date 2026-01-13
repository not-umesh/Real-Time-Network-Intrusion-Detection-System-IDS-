"""
Real-Time Network IDS Dashboard
Beautiful Streamlit dashboard for monitoring network traffic and intrusions.
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
import threading
from typing import Dict, List, Any
import json


# Page configuration
st.set_page_config(
    page_title="Network IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for beautiful dark theme with glassmorphism
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
    }
    
    /* Glassmorphism cards */
    .glass-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        padding: 20px;
        margin: 10px 0;
        box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.37);
    }
    
    /* Metric cards */
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
        text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: #a0a0a0;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Alert cards */
    .alert-critical {
        background: linear-gradient(135deg, rgba(255, 0, 0, 0.2) 0%, rgba(139, 0, 0, 0.2) 100%);
        border-left: 4px solid #ff0000;
    }
    
    .alert-high {
        background: linear-gradient(135deg, rgba(255, 140, 0, 0.2) 0%, rgba(255, 100, 0, 0.2) 100%);
        border-left: 4px solid #ff8c00;
    }
    
    .alert-medium {
        background: linear-gradient(135deg, rgba(255, 215, 0, 0.2) 0%, rgba(255, 180, 0, 0.2) 100%);
        border-left: 4px solid #ffd700;
    }
    
    .alert-low {
        background: linear-gradient(135deg, rgba(0, 255, 0, 0.1) 0%, rgba(0, 200, 0, 0.1) 100%);
        border-left: 4px solid #00ff00;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: rgba(15, 15, 35, 0.95);
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #ffffff !important;
    }
    
    /* Status indicators */
    .status-online {
        color: #00ff00;
        text-shadow: 0 0 10px #00ff00;
    }
    
    .status-offline {
        color: #ff0000;
        text-shadow: 0 0 10px #ff0000;
    }
    
    /* Pulse animation for live indicator */
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .pulse {
        animation: pulse 2s infinite;
    }
</style>
""", unsafe_allow_html=True)


class DashboardState:
    """Manages dashboard state and data"""
    
    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        
        # Time series data
        self.packet_counts = deque(maxlen=max_history)
        self.byte_counts = deque(maxlen=max_history)
        self.threat_scores = deque(maxlen=max_history)
        self.timestamps = deque(maxlen=max_history)
        
        # Alerts
        self.alerts: List[Dict] = []
        self.max_alerts = 100
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'total_flows': 0,
            'threats_detected': 0,
            'packets_per_sec': 0,
            'start_time': datetime.now()
        }
        
        # System health
        self.health = {
            'sniffer': False,
            'model': False,
            'telegram': False
        }
    
    def add_data_point(self, packets: int, bytes_: int, threat_score: float):
        """Add new data point"""
        now = datetime.now()
        self.packet_counts.append(packets)
        self.byte_counts.append(bytes_)
        self.threat_scores.append(threat_score)
        self.timestamps.append(now)
        
        self.stats['total_packets'] += packets
        self.stats['total_bytes'] += bytes_
    
    def add_alert(self, alert: Dict):
        """Add new alert"""
        self.alerts.insert(0, alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[:self.max_alerts]
        self.stats['threats_detected'] += 1
    
    def get_traffic_df(self) -> pd.DataFrame:
        """Get traffic data as DataFrame"""
        if not self.timestamps:
            return pd.DataFrame()
        
        return pd.DataFrame({
            'timestamp': list(self.timestamps),
            'packets': list(self.packet_counts),
            'bytes': list(self.byte_counts),
            'threat_score': list(self.threat_scores)
        })


# Initialize session state
if 'dashboard' not in st.session_state:
    st.session_state.dashboard = DashboardState()

if 'dark_mode' not in st.session_state:
    st.session_state.dark_mode = True


def create_traffic_chart(df: pd.DataFrame) -> go.Figure:
    """Create real-time traffic visualization"""
    if df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="Waiting for traffic data...",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color="#666")
        )
    else:
        fig = make_subplots(
            rows=2, cols=1,
            shared_xaxes=True,
            vertical_spacing=0.1,
            subplot_titles=('Packets/sec', 'Bytes/sec')
        )
        
        # Packets
        fig.add_trace(
            go.Scatter(
                x=df['timestamp'],
                y=df['packets'],
                mode='lines',
                fill='tozeroy',
                line=dict(color='#00d4ff', width=2),
                fillcolor='rgba(0, 212, 255, 0.2)',
                name='Packets'
            ),
            row=1, col=1
        )
        
        # Bytes
        fig.add_trace(
            go.Scatter(
                x=df['timestamp'],
                y=df['bytes'],
                mode='lines',
                fill='tozeroy',
                line=dict(color='#ff6b6b', width=2),
                fillcolor='rgba(255, 107, 107, 0.2)',
                name='Bytes'
            ),
            row=2, col=1
        )
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        height=400,
        margin=dict(l=20, r=20, t=40, b=20),
        showlegend=False,
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)'),
        xaxis2=dict(showgrid=False),
        yaxis2=dict(showgrid=True, gridcolor='rgba(255,255,255,0.1)')
    )
    
    return fig


def create_threat_gauge(threat_level: float) -> go.Figure:
    """Create threat level gauge"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=threat_level * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Level", 'font': {'color': '#fff', 'size': 16}},
        number={'suffix': '%', 'font': {'color': '#fff', 'size': 24}},
        gauge={
            'axis': {'range': [0, 100], 'tickcolor': '#fff'},
            'bar': {'color': '#00d4ff'},
            'bgcolor': 'rgba(0,0,0,0)',
            'bordercolor': 'rgba(255,255,255,0.2)',
            'steps': [
                {'range': [0, 30], 'color': 'rgba(0,255,0,0.3)'},
                {'range': [30, 70], 'color': 'rgba(255,255,0,0.3)'},
                {'range': [70, 100], 'color': 'rgba(255,0,0,0.3)'}
            ],
            'threshold': {
                'line': {'color': '#ff0000', 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        height=250,
        margin=dict(l=30, r=30, t=60, b=30)
    )
    
    return fig


def create_attack_distribution(alerts: List[Dict]) -> go.Figure:
    """Create attack type distribution chart"""
    if not alerts:
        attack_types = ['No Data']
        counts = [1]
    else:
        attack_counts = {}
        for alert in alerts:
            attack_type = alert.get('attack_type', 'Unknown')
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
        attack_types = list(attack_counts.keys())
        counts = list(attack_counts.values())
    
    colors = ['#ff6b6b', '#feca57', '#48dbfb', '#ff9ff3', '#54a0ff', '#5f27cd']
    
    fig = go.Figure(data=[go.Pie(
        labels=attack_types,
        values=counts,
        hole=0.6,
        marker=dict(colors=colors[:len(attack_types)]),
        textinfo='percent+label',
        textfont=dict(color='#fff')
    )])
    
    fig.update_layout(
        template='plotly_dark',
        paper_bgcolor='rgba(0,0,0,0)',
        height=300,
        margin=dict(l=20, r=20, t=20, b=20),
        showlegend=False,
        annotations=[dict(
            text='Attacks',
            x=0.5, y=0.5,
            font=dict(size=16, color='#fff'),
            showarrow=False
        )]
    )
    
    return fig


def render_metric_card(title: str, value: str, icon: str = "📊"):
    """Render a metric card"""
    st.markdown(f"""
    <div class="metric-card">
        <div style="font-size: 2rem;">{icon}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-label">{title}</div>
    </div>
    """, unsafe_allow_html=True)


def render_alert_card(alert: Dict):
    """Render an alert card"""
    severity = alert.get('severity', 'low').lower()
    severity_class = f"alert-{severity}"
    
    st.markdown(f"""
    <div class="glass-card {severity_class}">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong style="color: #fff;">{alert.get('attack_type', 'Unknown')}</strong>
            <span style="color: #aaa;">{alert.get('timestamp', '')}</span>
        </div>
        <div style="margin-top: 10px; color: #ccc;">
            📍 {alert.get('source', 'N/A')} → 🎯 {alert.get('target', 'N/A')}
        </div>
        <div style="margin-top: 5px; color: #888;">
            Confidence: {alert.get('confidence', 0)*100:.1f}%
        </div>
    </div>
    """, unsafe_allow_html=True)


def main():
    """Main dashboard function"""
    dashboard = st.session_state.dashboard
    
    # Header
    col1, col2, col3 = st.columns([1, 3, 1])
    with col1:
        st.image("https://img.icons8.com/fluency/96/000000/security-shield-green.png", width=60)
    with col2:
        st.markdown("""
        <h1 style='margin: 0; padding: 0;'>
            🛡️ Real-Time Network IDS
            <span class='pulse' style='color: #00ff00; font-size: 0.5em;'>● LIVE</span>
        </h1>
        """, unsafe_allow_html=True)
    with col3:
        st.caption(f"Updated: {datetime.now().strftime('%H:%M:%S')}")
    
    st.markdown("---")
    
    # Metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        render_metric_card(
            "Packets/sec",
            f"{dashboard.stats.get('packets_per_sec', 0):.0f}",
            "📦"
        )
    
    with col2:
        render_metric_card(
            "Active Flows",
            f"{dashboard.stats.get('total_flows', 0)}",
            "🔀"
        )
    
    with col3:
        render_metric_card(
            "Threats Today",
            f"{dashboard.stats.get('threats_detected', 0)}",
            "⚠️"
        )
    
    with col4:
        total_mb = dashboard.stats.get('total_bytes', 0) / (1024 * 1024)
        render_metric_card(
            "Data Processed",
            f"{total_mb:.1f} MB",
            "💾"
        )
    
    with col5:
        uptime = datetime.now() - dashboard.stats['start_time']
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        render_metric_card(
            "Uptime",
            f"{hours:02d}:{minutes:02d}:{seconds:02d}",
            "⏱️"
        )
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("### 📊 Network Traffic")
        traffic_df = dashboard.get_traffic_df()
        fig = create_traffic_chart(traffic_df)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("### 🎯 Threat Level")
        avg_threat = np.mean(list(dashboard.threat_scores)) if dashboard.threat_scores else 0
        fig = create_threat_gauge(avg_threat)
        st.plotly_chart(fig, use_container_width=True)
    
    # Second row
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("### 🚨 Recent Alerts")
        if dashboard.alerts:
            for alert in dashboard.alerts[:5]:
                render_alert_card(alert)
        else:
            st.markdown("""
            <div class="glass-card">
                <p style="color: #888; text-align: center;">
                    ✅ No threats detected. System is monitoring...
                </p>
            </div>
            """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("### 📈 Attack Distribution")
        fig = create_attack_distribution(dashboard.alerts)
        st.plotly_chart(fig, use_container_width=True)
    
    # System Health
    st.markdown("### 💚 System Health")
    health_col1, health_col2, health_col3 = st.columns(3)
    
    with health_col1:
        status = "🟢 Online" if dashboard.health['sniffer'] else "🔴 Offline"
        st.markdown(f"""
        <div class="glass-card">
            <strong>Packet Sniffer</strong>
            <div style="font-size: 1.5rem;">{status}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with health_col2:
        status = "🟢 Loaded" if dashboard.health['model'] else "🟡 Loading..."
        st.markdown(f"""
        <div class="glass-card">
            <strong>ML Model</strong>
            <div style="font-size: 1.5rem;">{status}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with health_col3:
        status = "🟢 Connected" if dashboard.health['telegram'] else "🔴 Not Configured"
        st.markdown(f"""
        <div class="glass-card">
            <strong>Telegram Alerts</strong>
            <div style="font-size: 1.5rem;">{status}</div>
        </div>
        """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## ⚙️ Settings")
        
        interface = st.selectbox(
            "Network Interface",
            ["en0", "en1", "lo0"],
            index=0
        )
        
        threshold = st.slider(
            "Anomaly Threshold",
            0.0, 1.0, 0.5, 0.05
        )
        
        st.markdown("---")
        
        st.markdown("## 📱 Telegram")
        bot_status = "✅ Configured" if st.session_state.get('telegram_configured') else "❌ Not Configured"
        st.markdown(f"Status: {bot_status}")
        
        if st.button("Test Alert"):
            st.info("Sending test alert...")
        
        st.markdown("---")
        
        st.markdown("## 📄 About")
        st.markdown("""
        **Real-Time Network IDS**  
        Version 1.0.0
        
        Powered by:
        - 🧠 KitNET ML Model
        - ⚡ Apple Core ML
        - 🐍 Python & Scapy
        """)
    
    # Auto-refresh
    time.sleep(0.5)
    st.rerun()


if __name__ == "__main__":
    main()
