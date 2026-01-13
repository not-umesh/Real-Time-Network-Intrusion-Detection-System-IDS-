"""
Alerts package for Real-Time Network IDS
"""
from .telegram_bot import (
    TelegramAlertBot,
    TelegramConfig,
    Alert,
    AlertSeverity,
    create_alert_from_detection,
    send_test_alert,
    ATTACK_TYPES
)

__all__ = [
    'TelegramAlertBot',
    'TelegramConfig',
    'Alert',
    'AlertSeverity',
    'create_alert_from_detection',
    'send_test_alert',
    'ATTACK_TYPES',
]
