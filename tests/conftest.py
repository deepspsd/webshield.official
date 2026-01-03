"""
Pytest configuration and fixtures for WebShield tests
"""

import sys
from pathlib import Path

import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def sample_urls():
    """Sample URLs for testing"""
    return {
        "safe": ["https://google.com", "https://github.com", "https://microsoft.com", "https://stackoverflow.com"],
        "malicious": [
            "http://192.168.1.1/login",
            "https://paypal-secure-verify.ga",
            "http://secure-bank-update123.tk",
            "https://microsoft-security-alert.cf",
        ],
    }


@pytest.fixture
def sample_content():
    """Sample HTML content for testing"""
    return {
        "safe": "<html><body><h1>Welcome</h1><p>Regular content</p></body></html>",
        "phishing": '<html><body><h1>URGENT</h1><p>Verify your password now!</p><form><input type="password"></form></body></html>',
    }


@pytest.fixture
def test_user():
    """Test user credentials"""
    return {"email": "test@webshield.com", "password": "TestPassword123!", "full_name": "Test User"}
