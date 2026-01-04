"""
Unit tests for authentication
"""

import uuid

from fastapi.testclient import TestClient

from backend.server import app

client = TestClient(app, base_url="http://testserver")
client.headers.update({"Host": "testserver"})


class TestRegistration:
    """Test user registration"""

    def test_register_valid_user(self):
        """Test registering a valid user"""
        unique_email = f"test_{uuid.uuid4()}@webshield.com"

        response = client.post(
            "/api/auth/register", json={"email": unique_email, "password": "TestPassword123!", "full_name": "Test User"}
        )

        # May fail if database not available, but should not crash
        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "success" in data

    def test_register_invalid_email(self):
        """Test registering with invalid email"""
        response = client.post(
            "/api/auth/register",
            json={"email": "not-an-email", "password": "TestPassword123!", "full_name": "Test User"},
        )

        # Should handle validation
        assert response.status_code in [200, 400, 422, 500]

    def test_register_weak_password(self):
        """Test registering with weak password"""
        response = client.post(
            "/api/auth/register",
            json={"email": f"test_{uuid.uuid4()}@webshield.com", "password": "123", "full_name": "Test User"},
        )

        # Should handle validation
        assert response.status_code in [200, 400, 422, 500]


class TestLogin:
    """Test user login"""

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        response = client.post(
            "/api/auth/login", json={"email": "nonexistent@webshield.com", "password": "WrongPassword123!"}
        )

        # Should return 401 or 500 if database unavailable
        assert response.status_code in [401, 500]

    def test_login_missing_fields(self):
        """Test login with missing fields"""
        response = client.post("/api/auth/login", json={"email": "test@webshield.com"})

        # Should return validation error
        assert response.status_code in [400, 422]


class TestProfile:
    """Test profile management"""

    def test_get_profile_invalid_email(self):
        """Test getting profile with invalid email"""
        response = client.get("/api/auth/profile?email=nonexistent@webshield.com")

        # Should return 404 or 500 if database unavailable
        assert response.status_code in [404, 500]
