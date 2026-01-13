"""
Tests for alert system.
"""
import pytest
import asyncio
from datetime import datetime
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

from alerts.telegram_bot import (
    Alert, AlertSeverity, TelegramConfig, TelegramAlertBot,
    create_alert_from_detection, ATTACK_TYPES
)
from models.feature_extractor import FlowKey


class TestAlert:
    """Test Alert dataclass"""
    
    def test_create_alert(self):
        """Test creating an Alert object"""
        alert = Alert(
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            attack_type="Port Scan",
            source_ip="192.168.1.100",
            source_port=54321,
            dest_ip="192.168.1.1",
            dest_port=22,
            confidence=0.95
        )
        
        assert alert.severity == AlertSeverity.HIGH
        assert alert.attack_type == "Port Scan"
        assert alert.confidence == 0.95
    
    def test_alert_to_telegram_message(self):
        """Test formatting alert as Telegram message"""
        alert = Alert(
            timestamp=datetime.now(),
            severity=AlertSeverity.CRITICAL,
            attack_type="DDoS Attack",
            source_ip="10.0.0.1",
            source_port=12345,
            dest_ip="10.0.0.2",
            dest_port=80,
            confidence=0.99
        )
        
        message = alert.to_telegram_message()
        
        assert "INTRUSION DETECTED" in message
        assert "DDoS Attack" in message
        assert "CRITICAL" in message
        assert "10.0.0.1:12345" in message
        assert "10.0.0.2:80" in message
    
    def test_alert_with_details(self):
        """Test alert with additional details"""
        alert = Alert(
            timestamp=datetime.now(),
            severity=AlertSeverity.MEDIUM,
            attack_type="Brute Force",
            source_ip="1.2.3.4",
            source_port=1000,
            dest_ip="5.6.7.8",
            dest_port=22,
            confidence=0.85,
            details={"attempts": 50, "target_service": "SSH"}
        )
        
        message = alert.to_telegram_message()
        
        assert "Details" in message
        assert "attempts" in message
        assert "SSH" in message


class TestAlertSeverity:
    """Test AlertSeverity enum"""
    
    def test_severity_values(self):
        """Test severity enum values"""
        assert AlertSeverity.INFO.value == "info"
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.CRITICAL.value == "critical"


class TestTelegramConfig:
    """Test TelegramConfig dataclass"""
    
    def test_default_config(self):
        """Test default configuration values"""
        config = TelegramConfig()
        
        assert config.max_alerts_per_minute == 10
        assert config.alert_cooldown == 5.0
        assert config.min_severity == AlertSeverity.LOW
    
    def test_config_from_env(self):
        """Test loading config from environment"""
        import os
        
        # Set test values
        os.environ["TELEGRAM_BOT_TOKEN"] = "test_token"
        os.environ["TELEGRAM_CHAT_ID"] = "test_chat"
        
        try:
            config = TelegramConfig.from_env()
            
            assert config.bot_token == "test_token"
            assert config.chat_id == "test_chat"
        finally:
            # Cleanup
            del os.environ["TELEGRAM_BOT_TOKEN"]
            del os.environ["TELEGRAM_CHAT_ID"]


class TestTelegramAlertBot:
    """Test TelegramAlertBot class"""
    
    def test_bot_not_configured(self):
        """Test bot is not configured without credentials"""
        config = TelegramConfig(bot_token="", chat_id="")
        bot = TelegramAlertBot(config)
        
        assert not bot.is_configured
    
    def test_bot_configured(self):
        """Test bot is configured with credentials"""
        config = TelegramConfig(bot_token="test_token", chat_id="test_chat")
        bot = TelegramAlertBot(config)
        
        assert bot.is_configured
    
    def test_get_stats(self):
        """Test getting bot statistics"""
        bot = TelegramAlertBot()
        stats = bot.get_stats()
        
        assert "sent" in stats
        assert "failed" in stats
        assert "rate_limited" in stats
        assert "filtered" in stats


class TestCreateAlertFromDetection:
    """Test create_alert_from_detection function"""
    
    def test_create_alert_high_confidence(self):
        """Test creating alert with high confidence"""
        flow_key = FlowKey("192.168.1.1", "192.168.1.2", 1234, 80, 6)
        
        alert = create_alert_from_detection(
            flow_key=flow_key,
            confidence=0.95,
            attack_type_id=11
        )
        
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.attack_type == "Port Scan"
        assert alert.source_ip == "192.168.1.1"
    
    def test_create_alert_medium_confidence(self):
        """Test creating alert with medium confidence"""
        flow_key = FlowKey("10.0.0.1", "10.0.0.2", 5555, 443, 6)
        
        alert = create_alert_from_detection(
            flow_key=flow_key,
            confidence=0.75,
            attack_type_id=3
        )
        
        assert alert.severity == AlertSeverity.MEDIUM
        assert alert.attack_type == "DDoS"
    
    def test_create_alert_with_details(self):
        """Test creating alert with details"""
        flow_key = FlowKey("1.1.1.1", "2.2.2.2", 100, 22, 6)
        
        alert = create_alert_from_detection(
            flow_key=flow_key,
            confidence=0.90,
            attack_type_id=12,
            details={"password_attempts": 100}
        )
        
        assert "password_attempts" in alert.details
        assert alert.details["password_attempts"] == 100


class TestAttackTypes:
    """Test attack type mappings"""
    
    def test_attack_types_defined(self):
        """Test all expected attack types are defined"""
        expected_types = [
            "Benign", "Bot", "Brute Force", "DDoS",
            "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
            "DoS Slowloris", "FTP-Patator", "Heartbleed",
            "Infiltration", "Port Scan", "SSH-Patator", "Web Attack"
        ]
        
        for attack_type in expected_types:
            assert attack_type in ATTACK_TYPES.values()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
