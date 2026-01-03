"""
WebShield Configuration Management
Centralized configuration with environment-based settings and secrets management
"""

import os
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings with environment variable support
    Uses pydantic for validation and type safety
    """

    # ============================================
    # APPLICATION SETTINGS
    # ============================================
    APP_NAME: str = "WebShield"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = Field(default="development", env="ENVIRONMENT")
    DEBUG: bool = Field(default=False, env="API_DEBUG")

    # ============================================
    # SERVER SETTINGS
    # ============================================
    API_HOST: str = Field(default="0.0.0.0", env="API_HOST")
    API_PORT: int = Field(default=8000, env="API_PORT")
    SERVER_WORKERS: int = Field(default=4, env="SERVER_WORKERS")

    # ============================================
    # SECURITY SETTINGS
    # ============================================
    SECRET_KEY: str = Field(..., env="SECRET_KEY")  
    JWT_SECRET: str = Field(..., env="JWT_SECRET")  
    JWT_EXPIRATION_HOURS: int = Field(default=24, env="JWT_EXPIRATION_HOURS")
    API_KEY_HEADER: str = "X-API-Key"
    
    # CORS Settings
    ALLOWED_ORIGINS: list = Field(
        default=["http://localhost:8000", "http://127.0.0.1:8000"],
        env="ALLOWED_ORIGINS"
    )
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    CORS_ALLOW_HEADERS: list = ["*"]

    # ============================================
    # DATABASE SETTINGS
    # ============================================
    DB_HOST: str = Field(..., env="DB_HOST")  
    DB_PORT: int = Field(default=3306, env="DB_PORT")
    DB_USER: str = Field(..., env="DB_USER")  
    DB_PASSWORD: str = Field(..., env="DB_PASSWORD")  
    DB_NAME: str = Field(..., env="DB_NAME")  
    DB_POOL_SIZE: int = Field(default=20, env="DB_POOL_SIZE")
    DB_SSL_CA: Optional[str] = Field(default=None, env="DB_SSL_CA")
    DB_SSL_MODE: str = Field(default="PREFERRED", env="DB_SSL_MODE")

    # ============================================
    # EXTERNAL API KEYS (Optional with fallbacks)
    # ============================================
    VT_API_KEY: Optional[str] = Field(default=None, env="VT_API_KEY")
    GEMINI_API_KEY: Optional[str] = Field(default=None, env="GEMINI_API_KEY")
    HUGGINGFACE_API_KEY: Optional[str] = Field(default=None, env="HUGGINGFACE_API_KEY")
    GROQ_API_KEY: Optional[str] = Field(default=None, env="GROQ_API_KEY")
    GROQ_EXPLANATION_MODEL: str = Field(
        default="llama-3.1-8b-instant", 
        env="GROQ_EXPLANATION_MODEL"
    )

    # ============================================
    # CACHING & PERFORMANCE
    # ============================================
    CACHE_TTL: int = Field(default=300, env="CACHE_TTL")
    CACHE_MAX_SIZE: int = Field(default=1000, env="CACHE_MAX_SIZE")
    
    # Redis (optional)
    REDIS_HOST: str = Field(default="localhost", env="REDIS_HOST")
    REDIS_PORT: int = Field(default=6379, env="REDIS_PORT")
    REDIS_PASSWORD: Optional[str] = Field(default=None, env="REDIS_PASSWORD")
    REDIS_DB: int = Field(default=0, env="REDIS_DB")

    # ============================================
    # RATE LIMITING
    # ============================================
    RATE_LIMIT_REQUESTS: int = Field(default=100, env="RATE_LIMIT_REQUESTS")
    RATE_LIMIT_WINDOW: int = Field(default=60, env="RATE_LIMIT_WINDOW")

    # ============================================
    # SCAN CONFIGURATION
    # ============================================
    SCAN_SSL_TIMEOUT: float = Field(default=3.0, env="SCAN_SSL_TIMEOUT")
    SCAN_CONTENT_TIMEOUT: float = Field(default=5.0, env="SCAN_CONTENT_TIMEOUT")
    SCAN_VIRUSTOTAL_TIMEOUT: float = Field(default=2.0, env="SCAN_VIRUSTOTAL_TIMEOUT")
    SCAN_CONTENT_MAX_BYTES: int = Field(default=5120, env="SCAN_CONTENT_MAX_BYTES")

    # ============================================
    # LOGGING
    # ============================================
    LOG_LEVEL: str = Field(default="INFO", env="LOG_LEVEL")
    ENABLE_ACCESS_LOGS: bool = Field(default=True, env="ENABLE_ACCESS_LOGS")
    LOG_FILE: str = Field(default="webshield.log", env="LOG_FILE")
    LOG_MAX_BYTES: int = Field(default=10485760, env="LOG_MAX_BYTES")  # 10MB
    LOG_BACKUP_COUNT: int = Field(default=5, env="LOG_BACKUP_COUNT")

    # ============================================
    # MONITORING
    # ============================================
    ENABLE_DOCS: bool = Field(default=True, env="ENABLE_DOCS")
    ENABLE_METRICS: bool = Field(default=True, env="ENABLE_METRICS")
    MONITOR_CHECK_INTERVAL: int = Field(default=30, env="MONITOR_CHECK_INTERVAL")

    # ============================================
    # EMAIL SETTINGS (Optional)
    # ============================================
    SMTP_HOST: Optional[str] = Field(default=None, env="SMTP_HOST")
    SMTP_PORT: int = Field(default=587, env="SMTP_PORT")
    SMTP_USER: Optional[str] = Field(default=None, env="SMTP_USER")
    SMTP_PASSWORD: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    SMTP_FROM: str = Field(default="noreply@webshield.com", env="SMTP_FROM")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @property
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.ENVIRONMENT.lower() == "production"

    @property
    def database_url(self) -> str:
        """Generate database connection URL"""
        return f"mysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    def get_cors_origins(self) -> list:
        """Get CORS origins as list"""
        if isinstance(self.ALLOWED_ORIGINS, str):
            return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",")]
        return self.ALLOWED_ORIGINS


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings"""
    return settings
