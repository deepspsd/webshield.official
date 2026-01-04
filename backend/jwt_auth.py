"""
JWT Authentication for WebShield
Provides secure token-based authentication
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

logger = logging.getLogger(__name__)

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

_environment = os.getenv("ENVIRONMENT", "development").lower()
if _environment in ("production", "prod"):
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET must be set to a strong secret in production")
else:
    if not JWT_SECRET:
        # Development fallback only (avoid breaking local setups)
        JWT_SECRET = "dev-jwt-secret-please-set-JWT_SECRET"  # nosec B105
        logger.warning("JWT_SECRET not set; using development fallback secret")

security = HTTPBearer()


def create_access_token(email: str, user_id: int) -> str:
    """
    Create JWT access token

    Args:
        email: User email
        user_id: User ID

    Returns:
        JWT token string
    """
    assert JWT_SECRET is not None, "JWT_SECRET must be configured"
    expiration = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)

    payload = {"sub": email, "user_id": user_id, "exp": expiration, "iat": datetime.utcnow()}

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_token(token: str) -> dict:
    """
    Verify and decode JWT token

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    assert JWT_SECRET is not None, "JWT_SECRET must be configured"
    try:
        payload: dict = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  # type: ignore[assignment]
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)) -> dict:
    """
    Get current user from JWT token

    Args:
        credentials: HTTP Authorization credentials

    Returns:
        User information from token
    """
    token = credentials.credentials
    payload = verify_token(token)
    return payload


def create_refresh_token(email: str, user_id: Optional[int] = None) -> str:
    """
    Create refresh token for extended sessions

    Args:
        email: User email
        user_id: User ID (optional)

    Returns:
        Refresh token string
    """
    assert JWT_SECRET is not None, "JWT_SECRET must be configured"
    expiration = datetime.utcnow() + timedelta(days=30)

    payload = {"sub": email, "type": "refresh", "exp": expiration, "iat": datetime.utcnow()}

    if user_id is not None:
        payload["user_id"] = user_id

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def refresh_access_token(refresh_token: str) -> str:
    """
    Generate new access token from refresh token

    Args:
        refresh_token: Refresh token string

    Returns:
        New access token
    """
    assert JWT_SECRET is not None, "JWT_SECRET must be configured"
    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        email = payload.get("sub")
        user_id = payload.get("user_id", 0)

        return create_access_token(email, user_id)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
