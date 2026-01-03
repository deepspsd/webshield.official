"""
Input Validation Layer for WebShield
Comprehensive validation for all user inputs to prevent injection attacks
"""

from pydantic import BaseModel, Field, HttpUrl, validator

try:
    from pydantic import EmailStr
except ImportError:
    # Fallback if email-validator is not installed
    EmailStr = str
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Whitelist of allowed column names for queries
ALLOWED_SCAN_COLUMNS = {
    "scan_id",
    "url",
    "status",
    "is_malicious",
    "threat_level",
    "malicious_count",
    "suspicious_count",
    "total_engines",
    "ssl_valid",
    "domain_reputation",
    "detection_details",
    "created_at",
    "completed_at",
    "scan_timestamp",
    "user_email",
}

ALLOWED_USER_COLUMNS = {
    "id",
    "email",
    "full_name",
    "created_at",
    "last_login",
    "profile_picture",
    "is_admin",
    "api_key",
}


class SafeURLValidator:
    """Comprehensive URL validation with security checks"""

    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and sanitize URL"""
        if not url or not isinstance(url, str):
            raise ValueError("URL must be a non-empty string")

        url = url.strip()

        # Check length
        if len(url) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")

        # Auto-prepend protocol if missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "https://" + url

        # Parse and validate
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")

            # Check for suspicious patterns
            if "@" in parsed.netloc and parsed.netloc.count("@") > 0:
                logger.warning(f"Suspicious URL with @ symbol: {url}")

            # Check for IP addresses (allowed but logged)
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.netloc):
                logger.info(f"URL uses IP address: {url}")

            return url

        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")

    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate domain name"""
        if not domain or not isinstance(domain, str):
            raise ValueError("Domain must be a non-empty string")

        domain = domain.strip().lower()

        # Check length
        if len(domain) > 253:
            raise ValueError("Domain exceeds maximum length")

        # Validate domain format
        domain_pattern = r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        if not re.match(domain_pattern, domain):
            raise ValueError("Invalid domain format")

        return domain


class SafeQueryValidator:
    """Validate database query parameters to prevent SQL injection"""

    @staticmethod
    def validate_column_name(column: str, allowed_columns: set) -> str:
        """Validate column name against whitelist"""
        if column not in allowed_columns:
            raise ValueError(f"Invalid column name: {column}")
        return column

    @staticmethod
    def validate_column_names(columns: List[str], allowed_columns: set) -> List[str]:
        """Validate multiple column names"""
        return [SafeQueryValidator.validate_column_name(col, allowed_columns) for col in columns]

    @staticmethod
    def validate_order_direction(direction: str) -> str:
        """Validate ORDER BY direction"""
        direction = direction.upper()
        if direction not in ("ASC", "DESC"):
            raise ValueError("Invalid order direction")
        return direction

    @staticmethod
    def validate_limit(limit: int, max_limit: int = 100) -> int:
        """Validate LIMIT value"""
        try:
            limit = int(limit)
            if limit < 1:
                return 1
            if limit > max_limit:
                return max_limit
            return limit
        except (ValueError, TypeError):
            return 10  # Default


class URLScanRequestValidated(BaseModel):
    """Validated URL scan request"""

    url: str = Field(..., description="URL to scan")
    user_email: Optional[EmailStr] = Field(None, description="User email address")
    scan_type: Optional[str] = Field("full", description="Type of scan to perform")

    @validator("url")
    def validate_url(cls, v):
        return SafeURLValidator.validate_url(v)

    @validator("scan_type")
    def validate_scan_type(cls, v):
        allowed_types = {"full", "quick", "deep"}
        if v not in allowed_types:
            raise ValueError(f"Invalid scan type. Allowed: {allowed_types}")
        return v


class RegisterRequestValidated(BaseModel):
    """Validated registration request"""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, max_length=128, description="User password")
    full_name: str = Field(..., min_length=2, max_length=100, description="User full name")
    confirm_password: Optional[str] = Field(None, description="Password confirmation")

    @validator("email")
    def validate_email_field(cls, v):
        return validate_email(v)

    @validator("password")
    def validate_password_strength(cls, v):
        """Validate password strength"""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")

        # Check for complexity
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)

        if not (has_upper and has_lower and has_digit):
            raise ValueError("Password must contain uppercase, lowercase, and digit")

        return v

    @validator("full_name")
    def validate_name(cls, v):
        """Validate name format"""
        # Remove extra whitespace
        v = " ".join(v.split())

        # Check for valid characters
        if not re.match(r"^[a-zA-Z\s\'-]+$", v):
            raise ValueError("Name contains invalid characters")

        return v

    @validator("confirm_password")
    def passwords_match(cls, v, values):
        """Validate password confirmation"""
        if "password" in values and v != values["password"]:
            raise ValueError("Passwords do not match")
        return v


class LoginRequestValidated(BaseModel):
    """Validated login request"""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")


class ReportRequestValidated(BaseModel):
    """Validated report request"""

    url: str = Field(..., description="URL to report")
    report_type: str = Field(..., description="Type of report")
    reason: Optional[str] = Field(None, max_length=1000, description="Reason for reporting")
    user_email: Optional[EmailStr] = Field(None, description="User email address")

    @validator("url")
    def validate_url(cls, v):
        return SafeURLValidator.validate_url(v)

    @validator("report_type")
    def validate_report_type(cls, v):
        allowed_types = {"blacklist", "whitelist", "false_positive", "feedback"}
        if v not in allowed_types:
            raise ValueError(f"Invalid report type. Allowed: {allowed_types}")
        return v

    @validator("reason")
    def validate_reason(cls, v):
        if v:
            # Remove potentially dangerous characters
            v = re.sub(r"[<>{}]", "", v)
            v = v.strip()
        return v


class ScanQueryParams(BaseModel):
    """Validated scan query parameters"""

    email: Optional[EmailStr] = None
    limit: Optional[int] = Field(10, ge=1, le=100)
    offset: Optional[int] = Field(0, ge=0)
    order_by: Optional[str] = Field("created_at", description="Column to order by")
    order_direction: Optional[str] = Field("DESC", description="Order direction")

    @validator("order_by")
    def validate_order_by(cls, v):
        return SafeQueryValidator.validate_column_name(v, ALLOWED_SCAN_COLUMNS)

    @validator("order_direction")
    def validate_direction(cls, v):
        return SafeQueryValidator.validate_order_direction(v)


class ApiKeyRequestValidated(BaseModel):
    """Validated API key request"""

    user_email: EmailStr = Field(..., description="User email address")
    name: str = Field(..., min_length=3, max_length=50, description="Name for the API key")
    permissions: Optional[Dict[str, Any]] = Field(default=None, description="API key permissions")
    rate_limits: Optional[Dict[str, Any]] = Field(default=None, description="Rate limit configuration")

    @validator("name")
    def validate_name(cls, v):
        # Remove special characters
        v = re.sub(r"[^a-zA-Z0-9\s_-]", "", v)
        return v.strip()


class BulkScanRequest(BaseModel):
    """Validated bulk scan request"""

    urls: List[str] = Field(..., min_items=1, max_items=100, description="List of URLs to scan")
    user_email: Optional[EmailStr] = Field(None, description="User email address")

    @validator("urls")
    def validate_urls(cls, v):
        """Validate all URLs in the list"""
        validated_urls = []
        for url in v:
            try:
                validated_url = SafeURLValidator.validate_url(url)
                validated_urls.append(validated_url)
            except ValueError as e:
                logger.warning(f"Invalid URL in bulk scan: {url} - {e}")
                # Skip invalid URLs but continue
                continue

        if not validated_urls:
            raise ValueError("No valid URLs provided")

        return validated_urls


# Sanitization utilities
class Sanitizer:
    """Sanitize user inputs"""

    @staticmethod
    def sanitize_html(text: str) -> str:
        """Remove HTML tags from text"""
        if not text:
            return ""
        # Remove HTML tags
        text = re.sub(r"<[^>]+>", "", text)
        return text.strip()

    @staticmethod
    def sanitize_sql_like(pattern: str) -> str:
        """Escape SQL LIKE wildcards"""
        if not pattern:
            return ""
        # Escape special characters
        pattern = pattern.replace("\\", "\\\\")
        pattern = pattern.replace("%", "\\%")
        pattern = pattern.replace("_", "\\_")
        return pattern

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe storage"""
        if not filename:
            return "unnamed"
        # Remove path traversal attempts
        filename = filename.replace("..", "")
        filename = filename.replace("/", "")
        filename = filename.replace("\\", "")
        # Keep only safe characters
        filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
        return filename[:255]  # Limit length


def validate_scan_id(scan_id: str) -> str:
    """Validate scan ID format"""
    if not scan_id or not isinstance(scan_id, str):
        raise ValueError("Invalid scan ID")

    # UUID format validation
    uuid_pattern = r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
    if not re.match(uuid_pattern, scan_id.lower()):
        raise ValueError("Invalid scan ID format")

    return scan_id.lower()


def validate_email(email: str) -> str:
    """Validate email format with comprehensive checks"""
    if not email:
        return email

    email = email.strip().lower()

    # Enhanced email validation regex
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        raise ValueError("Invalid email format")

    # Check email length
    if len(email) > 254:  # RFC 5321 limit
        raise ValueError("Email address too long")

    # Check for suspicious patterns
    suspicious_patterns = ["script", "javascript", "vbscript", "onload", "onerror", "<", ">", '"', "'"]
    if any(pattern in email.lower() for pattern in suspicious_patterns):
        raise ValueError("Email contains suspicious content")

    # Validate domain part
    try:
        local, domain = email.split("@")
        if len(local) > 64:  # RFC 5321 limit for local part
            raise ValueError("Email local part too long")
        if len(domain) > 253:  # RFC 1035 limit for domain
            raise ValueError("Email domain too long")
    except ValueError:
        raise ValueError("Invalid email format")

    return email
