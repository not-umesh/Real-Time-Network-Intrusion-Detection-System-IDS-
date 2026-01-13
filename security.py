"""
Security Utilities for Real-Time Network IDS
OWASP-compliant security measures: rate limiting, input validation, sanitization

Crafted with ☕ by UV
"""
import time
import hashlib
import re
import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict
from functools import wraps
import ipaddress


# ============================================================================
# Rate Limiting (IP + User-based)
# ============================================================================

@dataclass
class RateLimitConfig:
    """
    Rate limiting configuration following OWASP recommendations.
    Sensible defaults that balance security with usability.
    """
    # Requests per window
    requests_per_minute: int = 60        # General API limit
    requests_per_second: int = 10        # Burst protection
    alerts_per_minute: int = 30          # Alert endpoint specific
    
    # Sliding window size in seconds
    window_size: int = 60
    
    # Cooldown after hitting limit (seconds)
    lockout_duration: int = 300          # 5 minutes
    
    # Maximum violations before extended lockout
    max_violations: int = 5
    extended_lockout: int = 3600         # 1 hour


class RateLimiter:
    """
    IP + User-based rate limiter with sliding window algorithm.
    Returns graceful 429 responses when limits are exceeded.
    
    Usage:
        limiter = RateLimiter()
        allowed, error = limiter.check_rate_limit(ip_address, user_id)
        if not allowed:
            return {"error": error, "status": 429}
    """
    
    def __init__(self, config: RateLimitConfig = None):
        self.config = config or RateLimitConfig()
        
        # Sliding window storage: {key: [(timestamp, count), ...]}
        self._requests: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        
        # Violation tracking: {key: (count, lockout_until)}
        self._violations: Dict[str, Tuple[int, float]] = {}
        
        # Last cleanup time
        self._last_cleanup = time.time()
    
    def _get_key(self, ip: str, user_id: Optional[str] = None, endpoint: str = "default") -> str:
        """Generate unique rate limit key for IP + user combination."""
        # Sanitize inputs to prevent key injection
        safe_ip = self._sanitize_ip(ip)
        safe_user = self._sanitize_string(user_id or "anonymous", max_length=64)
        safe_endpoint = self._sanitize_string(endpoint, max_length=32)
        
        return f"{safe_ip}:{safe_user}:{safe_endpoint}"
    
    def _sanitize_ip(self, ip: str) -> str:
        """Validate and sanitize IP address."""
        try:
            # Validate IP format
            ip_obj = ipaddress.ip_address(ip)
            return str(ip_obj)
        except ValueError:
            # Invalid IP - return hash to prevent injection
            return hashlib.sha256(ip.encode()).hexdigest()[:16]
    
    def _sanitize_string(self, value: str, max_length: int = 128) -> str:
        """Sanitize string input."""
        if not value:
            return "unknown"
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '', str(value))
        return sanitized[:max_length]
    
    def _cleanup_old_entries(self):
        """Periodic cleanup of expired entries (every 5 minutes)."""
        now = time.time()
        if now - self._last_cleanup < 300:
            return
        
        cutoff = now - self.config.window_size * 2
        
        # Clean request history
        for key in list(self._requests.keys()):
            self._requests[key] = [(t, c) for t, c in self._requests[key] if t > cutoff]
            if not self._requests[key]:
                del self._requests[key]
        
        # Clean expired violations
        for key in list(self._violations.keys()):
            _, lockout_until = self._violations[key]
            if now > lockout_until:
                del self._violations[key]
        
        self._last_cleanup = now
    
    def check_rate_limit(
        self,
        ip: str,
        user_id: Optional[str] = None,
        endpoint: str = "default",
        limit: Optional[int] = None
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if request is allowed under rate limits.
        
        Returns:
            (allowed: bool, error_response: Optional[dict])
            
        Error response follows RFC 7231 format for graceful 429s:
        {
            "error": "rate_limit_exceeded",
            "message": "Too many requests. Please try again later.",
            "retry_after": seconds_until_retry,
            "limit": requests_per_minute,
            "remaining": 0
        }
        """
        self._cleanup_old_entries()
        
        now = time.time()
        key = self._get_key(ip, user_id, endpoint)
        effective_limit = limit or self.config.requests_per_minute
        
        # Check if currently locked out
        if key in self._violations:
            violation_count, lockout_until = self._violations[key]
            if now < lockout_until:
                retry_after = int(lockout_until - now)
                return False, {
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. You've been temporarily blocked. "
                               f"Please try again in {retry_after} seconds.",
                    "retry_after": retry_after,
                    "limit": effective_limit,
                    "remaining": 0,
                    "status": 429
                }
        
        # Count requests in current window
        window_start = now - self.config.window_size
        self._requests[key] = [(t, c) for t, c in self._requests[key] if t > window_start]
        
        total_requests = sum(c for _, c in self._requests[key])
        
        if total_requests >= effective_limit:
            # Rate limit exceeded - record violation
            self._record_violation(key, now)
            
            # Calculate retry time
            oldest_request = min(t for t, _ in self._requests[key]) if self._requests[key] else now
            retry_after = int(oldest_request + self.config.window_size - now) + 1
            
            return False, {
                "error": "rate_limit_exceeded",
                "message": f"Rate limit exceeded. Maximum {effective_limit} requests per minute. "
                           f"Please try again in {retry_after} seconds.",
                "retry_after": retry_after,
                "limit": effective_limit,
                "remaining": 0,
                "status": 429
            }
        
        # Request allowed - record it
        self._requests[key].append((now, 1))
        
        return True, None
    
    def _record_violation(self, key: str, now: float):
        """Record rate limit violation and apply lockout if needed."""
        if key in self._violations:
            count, _ = self._violations[key]
            count += 1
        else:
            count = 1
        
        # Determine lockout duration based on violation count
        if count >= self.config.max_violations:
            lockout = self.config.extended_lockout
        else:
            lockout = self.config.lockout_duration
        
        self._violations[key] = (count, now + lockout)
    
    def get_remaining(self, ip: str, user_id: Optional[str] = None, endpoint: str = "default") -> int:
        """Get remaining requests in current window."""
        key = self._get_key(ip, user_id, endpoint)
        now = time.time()
        window_start = now - self.config.window_size
        
        requests = [(t, c) for t, c in self._requests.get(key, []) if t > window_start]
        total = sum(c for _, c in requests)
        
        return max(0, self.config.requests_per_minute - total)


# ============================================================================
# Input Validation & Sanitization (Schema-based)
# ============================================================================

@dataclass
class ValidationRule:
    """Defines validation rules for a field."""
    field_type: type                      # Expected Python type
    required: bool = True                 # Is field required?
    min_length: Optional[int] = None      # Minimum string length
    max_length: Optional[int] = None      # Maximum string length
    min_value: Optional[float] = None     # Minimum numeric value
    max_value: Optional[float] = None     # Maximum numeric value
    pattern: Optional[str] = None         # Regex pattern for strings
    allowed_values: Optional[List] = None # Whitelist of allowed values
    sanitize: bool = True                 # Apply sanitization?
    custom_validator: Optional[callable] = None  # Custom validation function


class InputValidator:
    """
    Schema-based input validation following OWASP guidelines.
    
    - Type checking
    - Length limits
    - Pattern matching
    - Whitelist validation
    - Rejects unexpected fields
    - Sanitizes dangerous characters
    
    Usage:
        schema = {
            "interface": ValidationRule(str, max_length=10, pattern=r'^[a-z0-9]+$'),
            "threshold": ValidationRule(float, min_value=0.0, max_value=1.0),
        }
        validator = InputValidator(schema)
        is_valid, cleaned_data, errors = validator.validate(user_input)
    """
    
    # Dangerous patterns to sanitize (XSS, injection prevention)
    DANGEROUS_PATTERNS = [
        (r'<script[^>]*>.*?</script>', ''),           # Script tags
        (r'javascript:', ''),                          # JS protocol
        (r'on\w+\s*=', ''),                           # Event handlers
        (r'<[^>]+>', ''),                             # All HTML tags
        (r'[\x00-\x08\x0b\x0c\x0e-\x1f]', ''),        # Control characters
        (r'[\'\"`;]', ''),                            # SQL injection chars
    ]
    
    def __init__(self, schema: Dict[str, ValidationRule], reject_unknown: bool = True):
        """
        Initialize validator with schema.
        
        Args:
            schema: Dictionary mapping field names to ValidationRules
            reject_unknown: If True, reject any fields not in schema
        """
        self.schema = schema
        self.reject_unknown = reject_unknown
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], List[str]]:
        """
        Validate input data against schema.
        
        Returns:
            (is_valid, cleaned_data, error_messages)
        """
        errors = []
        cleaned = {}
        
        if not isinstance(data, dict):
            return False, {}, ["Input must be a dictionary/object"]
        
        # Check for unexpected fields
        if self.reject_unknown:
            unexpected = set(data.keys()) - set(self.schema.keys())
            if unexpected:
                errors.append(f"Unexpected fields rejected: {', '.join(unexpected)}")
        
        # Validate each field in schema
        for field_name, rule in self.schema.items():
            value = data.get(field_name)
            
            # Check required fields
            if value is None:
                if rule.required:
                    errors.append(f"Missing required field: {field_name}")
                continue
            
            # Type checking
            if not isinstance(value, rule.field_type):
                # Try type coercion for basic types
                try:
                    value = rule.field_type(value)
                except (ValueError, TypeError):
                    errors.append(f"Invalid type for {field_name}: expected {rule.field_type.__name__}")
                    continue
            
            # String validations
            if rule.field_type == str:
                # Sanitize if enabled
                if rule.sanitize:
                    value = self._sanitize_string(value)
                
                # Length checks
                if rule.min_length and len(value) < rule.min_length:
                    errors.append(f"{field_name} must be at least {rule.min_length} characters")
                    continue
                
                if rule.max_length and len(value) > rule.max_length:
                    errors.append(f"{field_name} must be at most {rule.max_length} characters")
                    continue
                
                # Pattern matching
                if rule.pattern and not re.match(rule.pattern, value):
                    errors.append(f"{field_name} has invalid format")
                    continue
            
            # Numeric validations
            if rule.field_type in (int, float):
                if rule.min_value is not None and value < rule.min_value:
                    errors.append(f"{field_name} must be at least {rule.min_value}")
                    continue
                
                if rule.max_value is not None and value > rule.max_value:
                    errors.append(f"{field_name} must be at most {rule.max_value}")
                    continue
            
            # Whitelist validation
            if rule.allowed_values and value not in rule.allowed_values:
                errors.append(f"{field_name} must be one of: {', '.join(map(str, rule.allowed_values))}")
                continue
            
            # Custom validator
            if rule.custom_validator:
                try:
                    is_valid, error_msg = rule.custom_validator(value)
                    if not is_valid:
                        errors.append(f"{field_name}: {error_msg}")
                        continue
                except Exception as e:
                    errors.append(f"{field_name}: validation error - {str(e)}")
                    continue
            
            cleaned[field_name] = value
        
        return len(errors) == 0, cleaned, errors
    
    def _sanitize_string(self, value: str) -> str:
        """Remove dangerous patterns from string."""
        sanitized = str(value)
        
        for pattern, replacement in self.DANGEROUS_PATTERNS:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
        
        # Normalize whitespace
        sanitized = ' '.join(sanitized.split())
        
        return sanitized.strip()


# Pre-defined schemas for common IDS inputs
IDS_CONFIG_SCHEMA = {
    "interface": ValidationRule(
        str, 
        max_length=10, 
        pattern=r'^[a-z0-9]+$',
        allowed_values=["en0", "en1", "eth0", "eth1", "wlan0", "lo0"]
    ),
    "threshold": ValidationRule(
        float,
        min_value=0.0,
        max_value=1.0
    ),
    "telegram_enabled": ValidationRule(
        bool,
        required=False
    ),
    "dashboard_enabled": ValidationRule(
        bool,
        required=False
    ),
}

ALERT_SCHEMA = {
    "attack_type": ValidationRule(
        str,
        max_length=50,
        pattern=r'^[a-zA-Z0-9\s\-_]+$'
    ),
    "source_ip": ValidationRule(
        str,
        max_length=45,  # IPv6 max length
        pattern=r'^[\d\.:a-fA-F]+$'
    ),
    "dest_ip": ValidationRule(
        str,
        max_length=45,
        pattern=r'^[\d\.:a-fA-F]+$'
    ),
    "source_port": ValidationRule(
        int,
        min_value=0,
        max_value=65535
    ),
    "dest_port": ValidationRule(
        int,
        min_value=0,
        max_value=65535
    ),
    "confidence": ValidationRule(
        float,
        min_value=0.0,
        max_value=1.0
    ),
}


# ============================================================================
# Secure API Key Handling
# ============================================================================

class SecureKeyManager:
    """
    Secure API key management following OWASP best practices.
    
    - Keys loaded from environment variables ONLY
    - No hardcoded keys
    - Key rotation support
    - Keys never exposed to client-side
    - Secure key validation
    
    Usage:
        key_manager = SecureKeyManager()
        telegram_token = key_manager.get_key("TELEGRAM_BOT_TOKEN")
        
        if not key_manager.validate_key_format("TELEGRAM_BOT_TOKEN", token):
            raise ValueError("Invalid token format")
    """
    
    # Key format patterns for validation
    KEY_PATTERNS = {
        "TELEGRAM_BOT_TOKEN": r'^\d+:[A-Za-z0-9_-]{35,}$',
        "TELEGRAM_CHAT_ID": r'^-?\d+$',
        "API_KEY": r'^[A-Za-z0-9_-]{32,}$',
    }
    
    # Required keys and their descriptions
    REQUIRED_KEYS = {
        "TELEGRAM_BOT_TOKEN": "Telegram bot API token from @BotFather",
        "TELEGRAM_CHAT_ID": "Your Telegram chat ID from @userinfobot",
    }
    
    # Optional keys
    OPTIONAL_KEYS = {
        "IDS_INTERFACE": "Network interface to monitor (default: en0)",
        "IDS_ANOMALY_THRESHOLD": "Detection threshold 0.0-1.0 (default: 0.5)",
    }
    
    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._load_time = time.time()
        self._max_cache_age = 3600  # Reload keys every hour for rotation
    
    def get_key(self, key_name: str, default: Optional[str] = None) -> Optional[str]:
        """
        Securely retrieve API key from environment.
        
        Args:
            key_name: Name of the environment variable
            default: Default value if not set
            
        Returns:
            Key value or default
        """
        # Refresh cache if expired (supports key rotation)
        if time.time() - self._load_time > self._max_cache_age:
            self._cache.clear()
            self._load_time = time.time()
        
        # Check cache first
        if key_name in self._cache:
            return self._cache[key_name]
        
        # Load from environment
        value = os.environ.get(key_name)
        
        if value:
            # Validate format if pattern exists
            if key_name in self.KEY_PATTERNS:
                if not self.validate_key_format(key_name, value):
                    # Log warning but don't expose key in error
                    print(f"⚠️ Warning: {key_name} has invalid format")
            
            self._cache[key_name] = value
            return value
        
        return default
    
    def validate_key_format(self, key_name: str, value: str) -> bool:
        """Validate key matches expected format."""
        if key_name not in self.KEY_PATTERNS:
            return True  # No pattern defined, assume valid
        
        pattern = self.KEY_PATTERNS[key_name]
        return bool(re.match(pattern, value))
    
    def is_configured(self, *key_names: str) -> bool:
        """Check if all specified keys are configured."""
        for key_name in key_names:
            if not self.get_key(key_name):
                return False
        return True
    
    def get_missing_keys(self) -> List[str]:
        """Get list of required keys that are not configured."""
        missing = []
        for key_name in self.REQUIRED_KEYS:
            if not self.get_key(key_name):
                missing.append(key_name)
        return missing
    
    def mask_key(self, value: str, visible_chars: int = 4) -> str:
        """
        Mask API key for safe logging/display.
        Shows only first and last few characters.
        """
        if not value or len(value) < visible_chars * 2:
            return "***"
        
        return f"{value[:visible_chars]}...{value[-visible_chars:]}"
    
    @staticmethod
    def generate_secure_key(length: int = 32) -> str:
        """Generate a cryptographically secure random key."""
        import secrets
        return secrets.token_urlsafe(length)
    
    def print_status(self):
        """Print configured key status (without exposing values)."""
        print("\n🔐 API Key Configuration Status:")
        print("-" * 40)
        
        for key_name, description in self.REQUIRED_KEYS.items():
            value = self.get_key(key_name)
            if value:
                masked = self.mask_key(value)
                print(f"  ✅ {key_name}: {masked}")
            else:
                print(f"  ❌ {key_name}: NOT SET")
                print(f"     → {description}")
        
        print()
        for key_name, description in self.OPTIONAL_KEYS.items():
            value = self.get_key(key_name)
            if value:
                print(f"  ✅ {key_name}: {value}")
            else:
                print(f"  ⚪ {key_name}: using default")


# ============================================================================
# Decorator for rate-limited endpoints
# ============================================================================

# Global rate limiter instance
_rate_limiter = RateLimiter()
_key_manager = SecureKeyManager()


def rate_limit(limit: int = 60, endpoint: str = "default"):
    """
    Decorator to apply rate limiting to functions.
    
    Usage:
        @rate_limit(limit=30, endpoint="alerts")
        def send_alert(ip, data):
            ...
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try to extract IP from kwargs or first arg
            ip = kwargs.get('ip', kwargs.get('client_ip', '127.0.0.1'))
            user_id = kwargs.get('user_id')
            
            allowed, error = _rate_limiter.check_rate_limit(ip, user_id, endpoint, limit)
            
            if not allowed:
                return error
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def validate_input(schema: Dict[str, ValidationRule]):
    """
    Decorator to validate function inputs against schema.
    
    Usage:
        @validate_input(IDS_CONFIG_SCHEMA)
        def configure_ids(config: dict):
            ...
    """
    def decorator(func):
        validator = InputValidator(schema)
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Find the dict argument to validate
            data = None
            for arg in args:
                if isinstance(arg, dict):
                    data = arg
                    break
            
            if data is None:
                data = kwargs.get('data', kwargs.get('config', {}))
            
            is_valid, cleaned, errors = validator.validate(data)
            
            if not is_valid:
                return {
                    "error": "validation_error",
                    "message": "Invalid input data",
                    "details": errors,
                    "status": 400
                }
            
            # Replace original data with cleaned data
            if 'data' in kwargs:
                kwargs['data'] = cleaned
            elif 'config' in kwargs:
                kwargs['config'] = cleaned
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ============================================================================
#                           Crafted with ☕ by UV
# ============================================================================
