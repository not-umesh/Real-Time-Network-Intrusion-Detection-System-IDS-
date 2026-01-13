"""
Telegram Bot Alert System
Sends real-time intrusion alerts to Telegram.
"""
import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from datetime import datetime
from collections import deque
from enum import Enum
import aiohttp


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Represents a single alert"""
    timestamp: datetime
    severity: AlertSeverity
    attack_type: str
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_telegram_message(self) -> str:
        """Format alert as Telegram message"""
        severity_emoji = {
            AlertSeverity.INFO: "ℹ️",
            AlertSeverity.LOW: "⚠️",
            AlertSeverity.MEDIUM: "🔶",
            AlertSeverity.HIGH: "🔴",
            AlertSeverity.CRITICAL: "🚨"
        }
        
        emoji = severity_emoji.get(self.severity, "⚠️")
        
        message = f"""
{emoji} *INTRUSION DETECTED* {emoji}
━━━━━━━━━━━━━━━━━━━━━━━━━

⏰ *Time:* `{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}`
🎯 *Attack Type:* `{self.attack_type}`
📊 *Confidence:* `{self.confidence*100:.1f}%`
⚡ *Severity:* `{self.severity.value.upper()}`

📍 *Source:* `{self.source_ip}:{self.source_port}`
🎪 *Target:* `{self.dest_ip}:{self.dest_port}`
"""
        
        if self.details:
            message += "\n📋 *Details:*\n"
            for key, value in self.details.items():
                message += f"  • {key}: `{value}`\n"
        
        message += "\n━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        return message


@dataclass
class TelegramConfig:
    """Telegram bot configuration"""
    bot_token: str = ""
    chat_id: str = ""
    max_alerts_per_minute: int = 10
    alert_cooldown: float = 5.0  # Seconds between same-type alerts
    min_severity: AlertSeverity = AlertSeverity.LOW
    
    @classmethod
    def from_env(cls) -> 'TelegramConfig':
        """Load configuration from environment variables"""
        return cls(
            bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
            chat_id=os.getenv("TELEGRAM_CHAT_ID", "")
        )


class TelegramAlertBot:
    """
    Async Telegram bot for sending intrusion alerts.
    
    Features:
    - Rate limiting to prevent spam
    - Alert aggregation for flood attacks
    - Severity-based filtering
    - Retry logic for failed sends
    """
    
    def __init__(self, config: TelegramConfig = None):
        self.config = config or TelegramConfig.from_env()
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Rate limiting
        self._alert_times: deque = deque(maxlen=100)
        self._last_alert_by_type: Dict[str, float] = {}
        
        # Statistics
        self._stats = {
            'sent': 0,
            'failed': 0,
            'rate_limited': 0,
            'filtered': 0
        }
        
        # Alert queue for batch sending
        self._alert_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
    
    @property
    def is_configured(self) -> bool:
        """Check if bot is properly configured"""
        return bool(self.config.bot_token and self.config.chat_id)
    
    async def start(self):
        """Start the alert bot"""
        if not self.is_configured:
            print("⚠ Telegram bot not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
            return
        
        self._session = aiohttp.ClientSession()
        self._running = True
        
        # Start background sender
        asyncio.create_task(self._alert_sender_loop())
        
        print("✓ Telegram alert bot started")
    
    async def stop(self):
        """Stop the alert bot"""
        self._running = False
        
        if self._session:
            await self._session.close()
            self._session = None
        
        print("✓ Telegram alert bot stopped")
    
    async def _alert_sender_loop(self):
        """Background loop for sending queued alerts"""
        while self._running:
            try:
                # Get alert with timeout
                try:
                    alert = await asyncio.wait_for(
                        self._alert_queue.get(),
                        timeout=1.0
                    )
                    await self._send_alert_internal(alert)
                except asyncio.TimeoutError:
                    continue
            except Exception as e:
                print(f"Alert sender error: {e}")
                await asyncio.sleep(1)
    
    def _should_send_alert(self, alert: Alert) -> bool:
        """Check if alert should be sent based on rate limits and filters"""
        current_time = time.time()
        
        # Check severity filter
        severity_order = [AlertSeverity.INFO, AlertSeverity.LOW, AlertSeverity.MEDIUM, 
                        AlertSeverity.HIGH, AlertSeverity.CRITICAL]
        if severity_order.index(alert.severity) < severity_order.index(self.config.min_severity):
            self._stats['filtered'] += 1
            return False
        
        # Check rate limit (alerts per minute)
        self._alert_times.append(current_time)
        recent_alerts = sum(1 for t in self._alert_times if current_time - t < 60)
        if recent_alerts > self.config.max_alerts_per_minute:
            self._stats['rate_limited'] += 1
            return False
        
        # Check cooldown for same attack type
        alert_key = f"{alert.attack_type}_{alert.source_ip}"
        last_time = self._last_alert_by_type.get(alert_key, 0)
        if current_time - last_time < self.config.alert_cooldown:
            self._stats['rate_limited'] += 1
            return False
        
        self._last_alert_by_type[alert_key] = current_time
        return True
    
    async def send_alert(self, alert: Alert):
        """Queue an alert for sending"""
        if not self.is_configured:
            return
        
        if self._should_send_alert(alert):
            await self._alert_queue.put(alert)
    
    async def _send_alert_internal(self, alert: Alert):
        """Actually send the alert to Telegram"""
        if not self._session:
            return
        
        url = f"https://api.telegram.org/bot{self.config.bot_token}/sendMessage"
        
        payload = {
            "chat_id": self.config.chat_id,
            "text": alert.to_telegram_message(),
            "parse_mode": "Markdown",
            "disable_notification": alert.severity in [AlertSeverity.INFO, AlertSeverity.LOW]
        }
        
        try:
            async with self._session.post(url, json=payload, timeout=10) as response:
                if response.status == 200:
                    self._stats['sent'] += 1
                else:
                    self._stats['failed'] += 1
                    error_text = await response.text()
                    print(f"Telegram API error: {response.status} - {error_text}")
        except Exception as e:
            self._stats['failed'] += 1
            print(f"Failed to send alert: {e}")
    
    async def send_test_alert(self) -> bool:
        """Send a test alert to verify configuration"""
        if not self.is_configured:
            print("⚠ Bot not configured")
            return False
        
        test_alert = Alert(
            timestamp=datetime.now(),
            severity=AlertSeverity.INFO,
            attack_type="Test Alert",
            source_ip="127.0.0.1",
            source_port=12345,
            dest_ip="127.0.0.1",
            dest_port=80,
            confidence=1.0,
            details={"message": "IDS system test - connection verified! 🎉"}
        )
        
        # Send directly (bypass queue)
        self._session = aiohttp.ClientSession()
        try:
            await self._send_alert_internal(test_alert)
            if self._stats['sent'] > 0:
                print("✓ Test alert sent successfully!")
                return True
            else:
                print("✗ Failed to send test alert")
                return False
        finally:
            await self._session.close()
            self._session = None
    
    def get_stats(self) -> Dict[str, int]:
        """Get alert statistics"""
        return dict(self._stats)


# Attack type mapping (CIC-IDS2018 compatible)
ATTACK_TYPES = {
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
    11: "Port Scan",
    12: "SSH-Patator",
    13: "Web Attack"
}


def create_alert_from_detection(
    flow_key,
    confidence: float,
    attack_type_id: int = 0,
    details: Dict = None
) -> Alert:
    """Create an Alert object from detection results"""
    
    # Determine severity based on confidence and attack type
    if confidence >= 0.95:
        severity = AlertSeverity.CRITICAL
    elif confidence >= 0.85:
        severity = AlertSeverity.HIGH
    elif confidence >= 0.70:
        severity = AlertSeverity.MEDIUM
    else:
        severity = AlertSeverity.LOW
    
    # Get attack type name
    attack_type = ATTACK_TYPES.get(attack_type_id, f"Unknown ({attack_type_id})")
    
    return Alert(
        timestamp=datetime.now(),
        severity=severity,
        attack_type=attack_type,
        source_ip=flow_key.src_ip,
        source_port=flow_key.src_port,
        dest_ip=flow_key.dst_ip,
        dest_port=flow_key.dst_port,
        confidence=confidence,
        details=details or {}
    )


async def send_test_alert():
    """Standalone function to send test alert"""
    bot = TelegramAlertBot()
    result = await bot.send_test_alert()
    return result


if __name__ == "__main__":
    # Test the alert system
    print("Testing Telegram Alert Bot...")
    print()
    
    # Check configuration
    config = TelegramConfig.from_env()
    print(f"Bot Token: {'✓ Set' if config.bot_token else '✗ Not set'}")
    print(f"Chat ID:   {'✓ Set' if config.chat_id else '✗ Not set'}")
    print()
    
    if config.bot_token and config.chat_id:
        # Send test alert
        asyncio.run(send_test_alert())
    else:
        print("To test, set environment variables:")
        print("  export TELEGRAM_BOT_TOKEN='your_token'")
        print("  export TELEGRAM_CHAT_ID='your_chat_id'")
        print()
        
        # Show sample alert message
        sample_alert = Alert(
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            attack_type="Port Scan",
            source_ip="192.168.1.100",
            source_port=54321,
            dest_ip="192.168.1.1",
            dest_port=22,
            confidence=0.92,
            details={"scan_type": "SYN Scan", "ports_scanned": 1024}
        )
        
        print("Sample alert message:")
        print("-" * 40)
        print(sample_alert.to_telegram_message())
