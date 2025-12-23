"""
Unit tests for ML models
"""

import pytest
import numpy as np
from backend.ml_models.ml_integration import MLSecurityEngine, get_ml_engine


class TestMLSecurityEngine:
    """Test ML Security Engine"""
    
    def test_engine_initialization(self):
        """Test ML engine initializes correctly"""
        engine = MLSecurityEngine(load_models=False)
        assert engine is not None
        assert engine.models_path.exists()
    
    def test_singleton_pattern(self):
        """Test global ML engine uses singleton pattern"""
        engine1 = get_ml_engine()
        engine2 = get_ml_engine()
        assert engine1 is engine2
    
    def test_url_feature_extraction(self, sample_urls):
        """Test URL feature extraction"""
        engine = MLSecurityEngine(load_models=False)
        
        for url in sample_urls['safe']:
            features = engine._extract_url_features(url)
            assert isinstance(features, np.ndarray)
            assert len(features) == 20
            assert features.dtype == np.float32
    
    def test_content_feature_extraction(self, sample_content):
        """Test content feature extraction"""
        engine = MLSecurityEngine(load_models=False)
        
        features = engine._extract_content_features(sample_content['safe'])
        assert isinstance(features, np.ndarray)
        assert len(features) == 20
        assert features.dtype == np.float32
    
    def test_url_analysis(self, sample_urls):
        """Test URL analysis with ML"""
        engine = get_ml_engine()
        
        # Test safe URL
        result = engine.analyze_url_ml(sample_urls['safe'][0])
        assert 'ml_enabled' in result
        assert 'prediction' in result
        assert 'threat_probability' in result
        assert 'confidence' in result
        
        # Test malicious URL
        result = engine.analyze_url_ml(sample_urls['malicious'][0])
        assert result['threat_probability'] >= 0.0
        assert result['threat_probability'] <= 1.0
    
    def test_content_analysis(self, sample_content):
        """Test content analysis with ML"""
        engine = get_ml_engine()
        
        # Test safe content
        result = engine.analyze_content_ml(sample_content['safe'])
        assert 'ml_enabled' in result
        assert 'phishing_probability' in result
        assert 'threat_detected' in result
        
        # Test phishing content
        result = engine.analyze_content_ml(sample_content['phishing'])
        assert result['phishing_probability'] >= 0.0
        assert result['phishing_probability'] <= 1.0
    
    def test_model_status(self):
        """Test model status reporting"""
        engine = get_ml_engine()
        status = engine.get_model_status()
        
        assert 'url_classifier_trained' in status
        assert 'content_detector_trained' in status
        assert 'models_loaded' in status
        assert 'total_models' in status
        assert isinstance(status['total_models'], int)
    
    def test_fallback_models(self):
        """Test fallback model training"""
        engine = MLSecurityEngine(load_models=False)
        engine._train_fallback_models()
        
        assert engine.url_classifier is not None
        assert engine.content_detector is not None
    
    def test_rule_based_url_analysis(self, sample_urls):
        """Test rule-based URL analysis fallback"""
        engine = MLSecurityEngine(load_models=False)
        
        result = engine._rule_based_url_analysis(sample_urls['malicious'][0])
        assert 'ml_enabled' in result
        assert result['ml_enabled'] is False
        assert 'suspicious_score' in result
        assert result['suspicious_score'] > 0
    
    def test_rule_based_content_analysis(self, sample_content):
        """Test rule-based content analysis fallback"""
        engine = MLSecurityEngine(load_models=False)
        
        result = engine._rule_based_content_analysis(sample_content['phishing'])
        assert 'ml_enabled' in result
        assert result['ml_enabled'] is False
        assert 'phishing_score' in result
        assert result['phishing_score'] > 0
    
    def test_error_handling(self):
        """Test error handling in ML analysis"""
        engine = get_ml_engine()
        
        # Test with invalid URL
        result = engine.analyze_url_ml("not-a-valid-url")
        assert 'ml_enabled' in result
        
        # Test with empty content
        result = engine.analyze_content_ml("")
        assert 'ml_enabled' in result
