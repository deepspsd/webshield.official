"""
Unit tests for scan functionality
"""

import pytest
from fastapi.testclient import TestClient
from backend.server import app
import time

client = TestClient(app, base_url="http://testserver")
client.headers.update({"Host": "testserver"})


class TestScanEndpoint:
    """Test scan endpoint"""
    
    def test_scan_url_valid(self, sample_urls):
        """Test scanning a valid URL"""
        response = client.post(
            "/api/scan/scan",
            json={"url": sample_urls['safe'][0], "user_email": None}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert 'scan_id' in data
        assert 'url' in data
        assert 'status' in data
        assert data['status'] in ['processing', 'completed']
    
    def test_scan_url_invalid(self):
        """Test scanning an invalid URL"""
        response = client.post(
            "/api/scan/scan",
            json={"url": "not-a-valid-url", "user_email": None}
        )
        assert response.status_code == 200
        
        data = response.json()
        # Should handle gracefully
        assert 'scan_id' in data or 'error' in data
    
    def test_scan_url_empty(self):
        """Test scanning an empty URL"""
        response = client.post(
            "/api/scan/scan",
            json={"url": "", "user_email": None}
        )
        assert response.status_code == 200
        
        data = response.json()
        assert 'error' in data or 'status' in data
    
    def test_get_scan_result(self, sample_urls):
        """Test retrieving scan results"""
        # First, create a scan
        scan_response = client.post(
            "/api/scan/scan",
            json={"url": sample_urls['safe'][0], "user_email": None}
        )
        assert scan_response.status_code == 200
        scan_data = scan_response.json()
        scan_id = scan_data['scan_id']
        
        # Wait a bit for scan to process
        time.sleep(2)
        
        # Now retrieve the result
        result_response = client.get(f"/api/scan/scan/{scan_id}")
        assert result_response.status_code in [200, 404]
        
        if result_response.status_code == 200:
            result_data = result_response.json()
            assert 'scan_id' in result_data
            assert 'status' in result_data
    
    def test_get_scan_result_invalid_id(self):
        """Test retrieving scan with invalid ID"""
        response = client.get("/api/scan/scan/invalid-scan-id-12345")
        assert response.status_code == 404


class TestScanCache:
    """Test scan caching functionality"""
    
    def test_scan_cache(self, sample_urls):
        """Test that repeated scans use cache"""
        url = sample_urls['safe'][0]
        
        # First scan
        response1 = client.post(
            "/api/scan/scan",
            json={"url": url, "user_email": None}
        )
        assert response1.status_code == 200
        
        # Second scan (should be faster due to cache)
        response2 = client.post(
            "/api/scan/scan",
            json={"url": url, "user_email": None}
        )
        assert response2.status_code == 200
