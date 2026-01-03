"""
Enhanced Security Features for WebShield
API key rotation, rate limiting, security headers, and threat protection
"""

import hashlib
import json
import logging
import re
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

# Security configuration
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes
API_KEY_LENGTH = 64
API_KEY_ROTATION_DAYS = 90

security = HTTPBearer()


class SecurityManager:
    """Advanced security management"""

    def __init__(self):
        self.failed_attempts = {}  # In production, use Redis
        self.api_keys = {}  # In production, use database
        self.rate_limits = {}

    def generate_api_key(self, user_id: int) -> str:
        """Generate secure API key"""
        key = secrets.token_urlsafe(API_KEY_LENGTH)
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        self.api_keys[key_hash] = {
            "user_id": user_id,
            "created_at": datetime.now(),
            "last_used": None,
            "usage_count": 0,
            "is_active": True,
        }

        return key

    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate API key and return user info"""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        if key_hash not in self.api_keys:
            return None

        key_info = self.api_keys[key_hash]

        if not key_info["is_active"]:
            return None

        # Check if key needs rotation
        age = datetime.now() - key_info["created_at"]
        if age.days > API_KEY_ROTATION_DAYS:
            logger.warning(f"API key for user {key_info['user_id']} needs rotation")

        # Update usage
        key_info["last_used"] = datetime.now()
        key_info["usage_count"] += 1

        return key_info

    def rotate_api_key(self, old_key: str, user_id: int) -> str:
        """Rotate API key"""
        old_key_hash = hashlib.sha256(old_key.encode()).hexdigest()

        # Deactivate old key
        if old_key_hash in self.api_keys:
            self.api_keys[old_key_hash]["is_active"] = False

        # Generate new key
        return self.generate_api_key(user_id)

    def check_rate_limit(self, identifier: str, limit: int, window: int) -> bool:
        """Check rate limit for identifier"""
        now = time.time()
        window_start = now - window

        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []

        # Remove old requests
        self.rate_limits[identifier] = [
            req_time for req_time in self.rate_limits[identifier] if req_time > window_start
        ]

        # Check limit
        if len(self.rate_limits[identifier]) >= limit:
            return False

        # Add current request
        self.rate_limits[identifier].append(now)
        return True

    def record_failed_login(self, identifier: str):
        """Record failed login attempt"""
        now = time.time()

        if identifier not in self.failed_attempts:
            self.failed_attempts[identifier] = []

        self.failed_attempts[identifier].append(now)

        # Clean old attempts
        cutoff = now - LOCKOUT_DURATION
        self.failed_attempts[identifier] = [attempt for attempt in self.failed_attempts[identifier] if attempt > cutoff]

    def is_locked_out(self, identifier: str) -> bool:
        """Check if identifier is locked out"""
        if identifier not in self.failed_attempts:
            return False

        now = time.time()
        cutoff = now - LOCKOUT_DURATION

        recent_attempts = [attempt for attempt in self.failed_attempts[identifier] if attempt > cutoff]

        return len(recent_attempts) >= MAX_LOGIN_ATTEMPTS

    def clear_failed_attempts(self, identifier: str):
        """Clear failed attempts after successful login"""
        if identifier in self.failed_attempts:
            del self.failed_attempts[identifier]


# Global security manager
security_manager = SecurityManager()


def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    # Check for forwarded headers
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    return request.client.host


def validate_input(data: str, max_length: int = 1000, allow_html: bool = False) -> str:
    """Validate and sanitize input"""
    if not data:
        return data

    # Length check
    if len(data) > max_length:
        raise HTTPException(status_code=400, detail="Input too long")

    # HTML sanitization
    if not allow_html:
        # Basic HTML entity encoding
        data = data.replace("<", "&lt;").replace(">", "&gt;")
        data = data.replace("'", "&#x27;").replace('"', "&quot;")

    return data


def check_sql_injection(query: str) -> bool:
    """Check for potential SQL injection patterns"""
    dangerous_patterns = [
        r"(\s|^)(union|select|insert|update|delete|drop|create|alter)\s",
        r"(\s|^)(or|and)\s+\d+\s*=\s*\d+",
        r"(\s|^)(or|and)\s+['\"].*['\"]",
        r"['\"];?\s*(drop|delete|insert|update)",
        r"\/\*.*\*\/",
        r"--.*$",
    ]

    query_lower = query.lower()

    for pattern in dangerous_patterns:
        if re.search(pattern, query_lower, re.IGNORECASE | re.MULTILINE):
            return True

    return False


def add_security_headers(response):
    """Add security headers to response"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

    # Content Security Policy
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https:; "
        "frame-ancestors 'none'"
    )
    response.headers["Content-Security-Policy"] = csp

    return response


class RateLimiter:
    """Advanced rate limiting"""

    def __init__(self, requests: int, window: int, identifier_func=None):
        self.requests = requests
        self.window = window
        self.identifier_func = identifier_func or get_client_ip

    def __call__(self, request: Request):
        identifier = self.identifier_func(request)

        if not security_manager.check_rate_limit(identifier, self.requests, self.window):
            raise HTTPException(
                status_code=429, detail="Rate limit exceeded", headers={"Retry-After": str(self.window)}
            )

        return True


# Rate limiters for different endpoints
scan_rate_limiter = RateLimiter(requests=10, window=60)  # 10 scans per minute
auth_rate_limiter = RateLimiter(requests=5, window=300)  # 5 auth attempts per 5 minutes
api_rate_limiter = RateLimiter(requests=100, window=60)  # 100 API calls per minute


def require_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Require valid API key"""
    api_key = credentials.credentials

    key_info = security_manager.validate_api_key(api_key)
    if not key_info:
        raise HTTPException(status_code=401, detail="Invalid API key")

    return key_info


def check_login_attempts(request: Request):
    """Check for too many failed login attempts"""
    client_ip = get_client_ip(request)

    if security_manager.is_locked_out(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed login attempts. Please try again later.")

    return True


class ThreatDetector:
    """Detect various security threats"""

    @staticmethod
    def detect_bot_traffic(request: Request) -> bool:
        """Detect potential bot traffic"""
        user_agent = request.headers.get("User-Agent", "").lower()

        bot_indicators = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "curl",
            "wget",
            "python-requests",
            "go-http-client",
            "java/",
            "okhttp",
        ]

        return any(indicator in user_agent for indicator in bot_indicators)

    @staticmethod
    def detect_suspicious_patterns(request: Request) -> List[str]:
        """Detect suspicious request patterns"""
        threats = []

        # Check for SQL injection in query parameters
        for param, value in request.query_params.items():
            if check_sql_injection(str(value)):
                threats.append(f"Potential SQL injection in parameter: {param}")

        # Check for XSS patterns
        for param, value in request.query_params.items():
            if "<script" in str(value).lower() or "javascript:" in str(value).lower():
                threats.append(f"Potential XSS in parameter: {param}")

        # Check for path traversal
        path = str(request.url.path)
        if "../" in path or "..%2f" in path.lower():
            threats.append("Potential path traversal attempt")

        return threats


# Security middleware
async def security_middleware(request: Request, call_next):
    """Security middleware for threat detection"""
    start_time = time.time()

    try:
        # Detect threats
        threat_detector = ThreatDetector()
        threats = threat_detector.detect_suspicious_patterns(request)

        if threats:
            logger.warning(f"Security threats detected from {get_client_ip(request)}: {threats}")
            # In production, you might want to block or rate limit these requests

        # Process request
        response = await call_next(request)

        # Add security headers
        response = add_security_headers(response)

        # Log security events
        if threats:
            logger.info(f"Request with threats processed: {request.method} {request.url.path}")

        return response

    except Exception as e:
        logger.error(f"Security middleware error: {e}")
        raise
