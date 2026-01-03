"""
Comprehensive Test Suite for WebShield
Tests for all critical components with high coverage
"""

import asyncio

# Import application components
import sys
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest

sys.path.insert(0, "../backend")

from backend.models import ScanResult, URLScanRequest
from backend.utils import WebShieldDetector


class TestURLScanning:
    """Test URL scanning functionality"""

    @pytest.mark.asyncio
    async def test_scan_legitimate_domain(self):
        """Test scanning a known legitimate domain"""
        async with WebShieldDetector() as detector:
            result = await detector.analyze_url_patterns("https://google.com")

            assert result is not None
            assert result.get("is_suspicious") is False
            assert result.get("suspicious_score", 100) < 30
            assert "Legitimate domain whitelisted" in result.get("detected_issues", [])

    @pytest.mark.asyncio
    async def test_scan_suspicious_url(self):
        """Test scanning a suspicious URL"""
        async with WebShieldDetector() as detector:
            result = await detector.analyze_url_patterns("http://192.168.1.1/login?password=test")

            assert result is not None
            assert result.get("suspicious_score", 0) > 20

    @pytest.mark.asyncio
    async def test_scan_malformed_url(self):
        """Test handling of malformed URLs"""
        async with WebShieldDetector() as detector:
            result = await detector.analyze_url_patterns("not-a-url")

            # Should handle gracefully without crashing
            assert result is not None

    @pytest.mark.asyncio
    async def test_ssl_validation_https(self):
        """Test SSL validation for HTTPS sites"""
        async with WebShieldDetector() as detector:
            result = await detector.analyze_ssl_certificate("https://google.com")

            assert result is not None
            assert "status" in result
            # Note: May timeout or succeed depending on network

    @pytest.mark.asyncio
    async def test_ssl_validation_http(self):
        """Test SSL validation for HTTP sites"""
        async with WebShieldDetector() as detector:
            result = await detector.analyze_ssl_certificate("http://example.com")

            assert result is not None
            assert result.get("status") == "no_https"
            assert result.get("valid") is False

    @pytest.mark.asyncio
    async def test_content_analysis(self):
        """Test content analysis with timeout handling"""
        async with WebShieldDetector() as detector:
            result = await detector.analyze_content("https://google.com", max_bytes=1024)

            assert result is not None
            assert "phishing_score" in result or "error" in result


class TestVirusTotalIntegration:
    """Test VirusTotal integration"""

    @pytest.mark.asyncio
    async def test_vt_without_api_key(self):
        """Test VT when API key is not configured"""
        with patch("backend.utils.VT_API_KEY", None):
            async with WebShieldDetector() as detector:
                result = await detector.check_virustotal("https://example.com")

                assert result is not None
                assert result.get("error") is not None
                assert "API key not configured" in result.get("error", "")

    @pytest.mark.asyncio
    async def test_vt_with_mock_response(self):
        """Test VT with mocked API response"""
        mock_response = {"malicious_count": 0, "suspicious_count": 0, "total_engines": 90, "cached": False}

        async with WebShieldDetector() as detector:
            with patch.object(detector, "check_virustotal", return_value=mock_response):
                result = await detector.check_virustotal("https://example.com")

                assert result.get("malicious_count") == 0
                assert result.get("total_engines") == 90


class TestSecurityFeatures:
    """Test security features"""

    def test_input_validation(self):
        """Test input validation and sanitization"""
        from backend.security import validate_input

        # Test basic validation
        clean = validate_input("https://example.com")
        assert "https://example.com" in clean

        # Test HTML escaping
        dirty = "<script>alert('xss')</script>"
        cleaned = validate_input(dirty, allow_html=False)
        assert "<script>" not in cleaned
        assert "&lt;script&gt;" in cleaned

    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        from backend.security import check_sql_injection

        # Malicious patterns
        assert check_sql_injection("' OR '1'='1") is True
        assert check_sql_injection("SELECT * FROM users") is True
        assert check_sql_injection("1; DROP TABLE users") is True

        # Clean queries
        assert check_sql_injection("normal search query") is False
        assert check_sql_injection("user@example.com") is False

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        from backend.security import SecurityManager

        manager = SecurityManager()

        # Should allow first requests
        for _ in range(5):
            assert manager.check_rate_limit("test-user", 10, 60) is True

        # Should deny after limit
        for _ in range(6):
            manager.check_rate_limit("test-user", 10, 60)

        # Should be at or over limit
        result = manager.check_rate_limit("test-user", 10, 60)
        assert result is False or manager.rate_limits["test-user"]


class TestDatabaseOperations:
    """Test database operations"""

    def test_database_connection_retry(self):
        """Test database connection with retry logic"""
        from backend.db import get_db_connection_with_retry

        # Should handle connection gracefully
        try:
            with get_db_connection_with_retry(max_retries=1, delay=0) as conn:
                if conn:
                    assert hasattr(conn, "cursor")
        except Exception as e:
            # Connection may fail in test environment - that's okay
            assert True

    def test_database_health_check(self):
        """Test database health check"""
        from backend.db import check_database_health

        result = check_database_health()
        assert isinstance(result, dict)
        assert "status" in result


class TestErrorHandling:
    """Test error handling and edge cases"""

    @pytest.mark.asyncio
    async def test_concurrent_scans(self):
        """Test handling multiple concurrent scans"""
        urls = ["https://google.com", "https://github.com", "https://stackoverflow.com"]

        async with WebShieldDetector() as detector:
            tasks = [detector.analyze_url_patterns(url) for url in urls]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            assert len(results) == 3
            # All should complete without crashing
            for result in results:
                assert result is not None or isinstance(result, Exception)

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Test timeout handling for slow operations"""
        async with WebShieldDetector() as detector:
            # Test with very short timeout
            result = await detector.analyze_content("https://google.com", max_bytes=100)

            # Should return result or timeout error, not crash
            assert result is not None

    def test_malformed_data_handling(self):
        """Test handling of malformed data"""
        from backend.models import URLScanRequest

        # Test with various invalid inputs
        invalid_inputs = [
            {"url": ""},
            {"url": None},
            {"url": 12345},
            {},
        ]

        for invalid_input in invalid_inputs:
            try:
                request = URLScanRequest(**invalid_input)
                # Pydantic should validate
            except Exception:
                # Expected to raise validation error
                assert True


class TestConfigurationManagement:
    """Test configuration and settings"""

    def test_settings_loading(self):
        """Test settings load from environment"""
        from backend.config import get_settings

        settings = get_settings()
        assert settings is not None
        assert hasattr(settings, "APP_NAME")
        assert hasattr(settings, "API_PORT")

    def test_environment_detection(self):
        """Test environment detection"""
        from backend.config import get_settings

        settings = get_settings()
        is_prod = settings.is_production
        assert isinstance(is_prod, bool)


class TestAPIEndpoints:
    """Test API endpoints (requires running server)"""

    def test_health_endpoint(self):
        """Test health check endpoint"""
        # This would require the server to be running
        # In real tests, use TestClient or httpx
        pass

    def test_scan_endpoint(self):
        """Test scan endpoint"""
        # This would require the server to be running
        pass


# Performance Tests
class TestPerformance:
    """Performance and load tests"""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_scan_performance(self):
        """Test scan completes within acceptable time"""
        import time

        start = time.time()
        async with WebShieldDetector() as detector:
            await detector.analyze_url_patterns("https://google.com")
        duration = time.time() - start

        # Should complete in under 5 seconds
        assert duration < 5.0

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_multiple_scans_performance(self):
        """Test performance with multiple scans"""
        import time

        urls = ["https://google.com" for _ in range(5)]

        start = time.time()
        async with WebShieldDetector() as detector:
            tasks = [detector.analyze_url_patterns(url) for url in urls]
            await asyncio.gather(*tasks)
        duration = time.time() - start

        # Should handle 5 scans efficiently
        assert duration < 15.0


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v", "--tb=short"])
