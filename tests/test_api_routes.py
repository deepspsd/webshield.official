"""
Unit tests for API routes
"""

import pytest
from fastapi.testclient import TestClient
from backend.server import app

client = TestClient(app, base_url="http://testserver")
client.headers.update({"Host": "testserver"})


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        """Test health endpoint returns correct status"""
        response = client.get("/api/health")
        assert response.status_code == 200
        
        data = response.json()
        assert 'status' in data
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert 'database' in data


class TestDashboardStats:
    """Test dashboard statistics endpoint"""
    
    def test_dashboard_stats(self):
        """Test dashboard stats endpoint"""
        response = client.get("/api/admin/dashboard-stats")
        assert response.status_code == 200
        
        data = response.json()
        assert 'urls_scanned' in data
        assert 'threats_blocked' in data
        assert 'users' in data
        assert isinstance(data['urls_scanned'], int)
        assert isinstance(data['threats_blocked'], int)


class TestMLTrainingStats:
    """Test ML training statistics endpoint"""
    
    def test_ml_training_stats(self):
        """Test ML training stats endpoint"""
        response = client.get("/api/admin/ml-training-stats")
        assert response.status_code == 200
        
        data = response.json()
        assert 'success' in data
        assert 'ml_models' in data
        assert isinstance(data['ml_models'], list)


class TestPoolStatus:
    """Test database pool status endpoint"""
    
    def test_pool_status(self):
        """Test pool status endpoint"""
        response = client.get("/api/admin/pool-status")
        assert response.status_code == 200
        
        data = response.json()
        assert 'success' in data
        assert 'pool_status' in data
