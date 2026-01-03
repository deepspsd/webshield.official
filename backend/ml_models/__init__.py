# ML Models Package for WebShield
# This package contains machine learning models for threat detection

__version__ = "1.0.0"
__author__ = "WebShield Team"

# Import key components to make them available at package level
try:
    from .content_analyzer import ContentPhishingDetector
    from .ml_integration import MLSecurityEngine, get_ml_engine
    from .url_classifier import URLThreatClassifier
except ImportError as e:
    # If imports fail, create dummy classes to prevent crashes
    import logging

    logger = logging.getLogger(__name__)
    logger.warning(f"Failed to import ML models: {e}")

    class MLSecurityEngine:
        def __init__(self):
            pass

        def analyze_url_ml(self, url):
            return {"ml_enabled": False, "prediction": 0}

    class URLThreatClassifier:
        def __init__(self):
            pass

        def predict(self, *args, **kwargs):
            return [0]

    class ContentPhishingDetector:
        def __init__(self):
            pass

        def analyze_content(self, content):
            return {"threat_detected": False, "confidence": 0.0}

    def get_ml_engine():
        return MLSecurityEngine()


# Export the main classes
__all__ = ["MLSecurityEngine", "URLThreatClassifier", "ContentPhishingDetector", "get_ml_engine"]
