"""
Configuration for Real-Time Network Intrusion Detection System
Optimized for MacBook Air M1 (Apple Silicon)
"""
import os
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

# Base directories
PROJECT_ROOT = Path(__file__).parent.absolute()
MODELS_DIR = PROJECT_ROOT / "models" / "pretrained"
LOGS_DIR = PROJECT_ROOT / "logs"


@dataclass
class NetworkConfig:
    """Network capture configuration"""
    interface: str = "en0"  # Default WiFi interface on Mac
    capture_filter: str = "ip"  # BPF filter
    flow_timeout: int = 120  # Seconds before flow expires
    max_packets_per_flow: int = 1000
    packet_queue_size: int = 10000
    

@dataclass
class ModelConfig:
    """ML Model configuration"""
    model_path: Path = MODELS_DIR / "kitnet_cicids2018.mlmodel"
    pytorch_path: Path = MODELS_DIR / "kitnet_cicids2018.pt"
    scaler_path: Path = MODELS_DIR / "scaler.pkl"
    
    # KitNET architecture
    num_features: int = 115  # CIC-IDS2018 feature count
    ensemble_size: int = 10  # Number of autoencoders
    hidden_ratio: float = 0.75  # Compression ratio
    
    # Anomaly detection
    anomaly_threshold: float = 0.5  # RMSE threshold
    use_coreml: bool = True  # Use Core ML for M1 acceleration
    batch_size: int = 32


@dataclass
class TelegramConfig:
    """Telegram alert configuration"""
    bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))
    chat_id: str = field(default_factory=lambda: os.getenv("TELEGRAM_CHAT_ID", ""))
    
    # Rate limiting
    max_alerts_per_minute: int = 10
    alert_cooldown: int = 5  # Seconds between same-type alerts
    
    # Alert severity thresholds
    severity_thresholds: dict = field(default_factory=lambda: {
        "low": 0.5,
        "medium": 0.7,
        "high": 0.85,
        "critical": 0.95
    })


@dataclass
class DashboardConfig:
    """Streamlit dashboard configuration"""
    host: str = "localhost"
    port: int = 8501
    theme: str = "dark"
    refresh_interval: float = 0.5  # Seconds
    max_history_points: int = 1000
    

@dataclass
class Config:
    """Main configuration container"""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    
    # System settings
    log_level: str = "INFO"
    log_file: Path = LOGS_DIR / "ids.log"
    debug: bool = False
    

# Attack type labels (CIC-IDS2018 compatible)
ATTACK_LABELS = {
    0: "Benign",
    1: "Bot",
    2: "Brute Force",
    3: "DDoS",
    4: "DoS GoldenEye",
    5: "DoS Hulk",
    6: "DoS Slowhttptest",
    7: "DoS Slowloris",
    8: "FTP-Patator",
    9: "Heartbleed",
    10: "Infiltration",
    11: "PortScan",
    12: "SSH-Patator",
    13: "Web Attack",
}

# Feature names for CIC-IDS2018 style extraction
FEATURE_NAMES = [
    "flow_duration", "total_fwd_packets", "total_bwd_packets",
    "total_length_fwd_packets", "total_length_bwd_packets",
    "fwd_packet_length_max", "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_max", "bwd_packet_length_min", "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes_per_sec", "flow_packets_per_sec",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_length", "bwd_header_length",
    "fwd_packets_per_sec", "bwd_packets_per_sec",
    "min_packet_length", "max_packet_length", "packet_length_mean", "packet_length_std", "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "cwe_flag_count", "ece_flag_count",
    "down_up_ratio", "average_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "fwd_header_length_1", "fwd_avg_bytes_per_bulk", "fwd_avg_packets_per_bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes_per_bulk", "bwd_avg_packets_per_bulk", "bwd_avg_bulk_rate",
    "subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_fwd", "init_win_bytes_bwd",
    "act_data_pkt_fwd", "min_seg_size_fwd",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
]


def get_config() -> Config:
    """Get the default configuration"""
    return Config()


def load_config_from_env() -> Config:
    """Load configuration with environment variable overrides"""
    config = Config()
    
    # Override from environment
    if interface := os.getenv("IDS_INTERFACE"):
        config.network.interface = interface
    
    if threshold := os.getenv("IDS_ANOMALY_THRESHOLD"):
        config.model.anomaly_threshold = float(threshold)
    
    return config
