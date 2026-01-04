#!/usr/bin/env python3
"""
WebShield Performance Configuration
Centralized configuration for all performance-related settings
"""

import os
from typing import Any, Dict


class PerformanceConfig:
    """Performance configuration class"""

    # Server Configuration
    SERVER_HOST = os.getenv("SERVER_HOST", "0.0.0.0")  # nosec B104
    SERVER_PORT = int(os.getenv("SERVER_PORT", "8000"))
    SERVER_WORKERS = int(os.getenv("SERVER_WORKERS", "1"))
    SERVER_RELOAD = os.getenv("SERVER_RELOAD", "false").lower() == "true"

    # Database Configuration
    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "20"))
    DB_CONNECTION_TIMEOUT = int(os.getenv("DB_CONNECTION_TIMEOUT", "10"))
    DB_POOL_RECYCLE = int(os.getenv("DB_POOL_RECYCLE", "3600"))

    # Rate Limiting
    RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds

    # Scan Timeouts
    SCAN_SSL_TIMEOUT = float(os.getenv("SCAN_SSL_TIMEOUT", "3.0"))
    SCAN_CONTENT_TIMEOUT = float(os.getenv("SCAN_CONTENT_TIMEOUT", "5.0"))
    SCAN_VIRUSTOTAL_TIMEOUT = float(os.getenv("SCAN_VIRUSTOTAL_TIMEOUT", "2.0"))
    SCAN_CONTENT_MAX_BYTES = int(os.getenv("SCAN_CONTENT_MAX_BYTES", "5120"))  # 5KB

    # Cache Configuration
    CACHE_TTL = int(os.getenv("CACHE_TTL", "180"))  # 3 minutes
    CACHE_MAX_SIZE = int(os.getenv("CACHE_MAX_SIZE", "1000"))

    # Request Timeouts
    REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15.0"))
    KEEP_ALIVE_TIMEOUT = int(os.getenv("KEEP_ALIVE_TIMEOUT", "5"))
    GRACEFUL_SHUTDOWN_TIMEOUT = int(os.getenv("GRACEFUL_SHUTDOWN_TIMEOUT", "10"))

    # Concurrency Limits
    MAX_CONCURRENT_CONNECTIONS = int(os.getenv("MAX_CONCURRENT_CONNECTIONS", "100"))
    MAX_REQUESTS_PER_WORKER = int(os.getenv("MAX_REQUESTS_PER_WORKER", "1000"))

    # Logging Configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "WARNING")
    ENABLE_ACCESS_LOGS = os.getenv("ENABLE_ACCESS_LOGS", "false").lower() == "true"
    ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() == "true"

    # Monitoring Configuration
    MONITOR_CHECK_INTERVAL = int(os.getenv("MONITOR_CHECK_INTERVAL", "30"))
    MONITOR_MAX_MEMORY_MB = int(os.getenv("MONITOR_MAX_MEMORY_MB", "512"))
    MONITOR_MAX_CPU_PERCENT = int(os.getenv("MONITOR_MAX_CPU_PERCENT", "80"))
    MONITOR_MAX_RESTARTS = int(os.getenv("MONITOR_MAX_RESTARTS", "5"))

    # GZip Configuration
    GZIP_MIN_SIZE = int(os.getenv("GZIP_MIN_SIZE", "500"))

    # CORS Configuration
    CORS_MAX_AGE = int(os.getenv("CORS_MAX_AGE", "3600"))

    @classmethod
    def get_server_config(cls) -> Dict[str, Any]:
        """Get server configuration for uvicorn"""
        return {
            "host": cls.SERVER_HOST,
            "port": cls.SERVER_PORT,
            "workers": cls.SERVER_WORKERS,
            "reload": cls.SERVER_RELOAD,
            "log_level": cls.LOG_LEVEL.lower(),
            "access_log": cls.ENABLE_ACCESS_LOGS,
            "http": "h11",
            "loop": "asyncio",
            "limit_concurrency": cls.MAX_CONCURRENT_CONNECTIONS,
            "limit_max_requests": cls.MAX_REQUESTS_PER_WORKER,
            "timeout_keep_alive": cls.KEEP_ALIVE_TIMEOUT,
            "timeout_graceful_shutdown": cls.GRACEFUL_SHUTDOWN_TIMEOUT,
        }

    @classmethod
    def get_database_config(cls) -> Dict[str, Any]:
        """Get database configuration"""
        return {
            "pool_size": cls.DB_POOL_SIZE,
            "connection_timeout": cls.DB_CONNECTION_TIMEOUT,
            "pool_recycle": cls.DB_POOL_RECYCLE,
        }

    @classmethod
    def get_rate_limit_config(cls) -> str:
        """Get rate limit configuration string"""
        return f"{cls.RATE_LIMIT_REQUESTS}/{cls.RATE_LIMIT_WINDOW}"

    @classmethod
    def get_scan_timeouts(cls) -> Dict[str, float]:
        """Get scan timeout configuration"""
        return {
            "ssl": cls.SCAN_SSL_TIMEOUT,
            "content": cls.SCAN_CONTENT_TIMEOUT,
            "virustotal": cls.SCAN_VIRUSTOTAL_TIMEOUT,
            "content_max_bytes": cls.SCAN_CONTENT_MAX_BYTES,
        }

    @classmethod
    def print_config(cls):
        """Print current configuration"""
        print("=== WebShield Performance Configuration ===")
        print(f"Server: {cls.SERVER_HOST}:{cls.SERVER_PORT}")
        print(f"Workers: {cls.SERVER_WORKERS}")
        print(f"Database Pool Size: {cls.DB_POOL_SIZE}")
        print(f"Rate Limit: {cls.get_rate_limit_config()}")
        print(f"Request Timeout: {cls.REQUEST_TIMEOUT}s")
        print(f"Scan Timeouts: {cls.get_scan_timeouts()}")
        print(f"Cache TTL: {cls.CACHE_TTL}s")
        print(f"Max Connections: {cls.MAX_CONCURRENT_CONNECTIONS}")
        print(f"Log Level: {cls.LOG_LEVEL}")
        print("==========================================")


# Environment-specific configurations
class DevelopmentConfig(PerformanceConfig):
    """Development environment configuration"""

    SERVER_RELOAD = True
    LOG_LEVEL = "INFO"
    ENABLE_ACCESS_LOGS = True
    ENABLE_DOCS = True
    CACHE_TTL = 60  # 1 minute for development
    REQUEST_TIMEOUT = 30.0  # Longer timeout for development


class ProductionConfig(PerformanceConfig):
    """Production environment configuration"""

    SERVER_WORKERS = 4
    DB_POOL_SIZE = 50
    CACHE_TTL = 300  # 5 minutes for production
    LOG_LEVEL = "ERROR"
    ENABLE_ACCESS_LOGS = False
    ENABLE_DOCS = False


# Get configuration based on environment
def get_config():
    """Get configuration based on environment"""
    env = os.getenv("ENVIRONMENT", "development").lower()

    if env == "production":
        return ProductionConfig()
    else:
        return DevelopmentConfig()


# Export configuration
config = get_config()

if __name__ == "__main__":
    config.print_config()
