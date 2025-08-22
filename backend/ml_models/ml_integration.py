"""
Top-level ML Integration for WebShield
This version imports models from the top-level ml_models package.
"""

import logging
import threading
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
import pandas as pd
import joblib
from urllib.parse import urlparse
import re

from .url_classifier import URLThreatClassifier
from .url_classifier import generate_training_data as generate_url_training_data
from .content_analyzer import ContentPhishingDetector
from .content_analyzer import generate_content_training_data

logger = logging.getLogger(__name__)

try:
    from bs4 import BeautifulSoup  # noqa: F401
    _BS4_AVAILABLE = True
except Exception:
    _BS4_AVAILABLE = False


class MLSecurityEngine:
    def __init__(self, load_models: bool = True):
        self.models_loaded = False
        self.url_classifier = None
        self.content_detector = None
        self._content_vectorizer = None
        self.models_path = Path(__file__).parent / 'saved_models'
        if load_models:
            self.load_models()

    def load_models(self) -> bool:
        try:
            logger.info("Loading ML models (top-level)...")
            preferred_url_models = [
                'enhanced_url_classifier_rf_kaggle.joblib',
                'enhanced_url_classifier_gb_kaggle.joblib',
                'url_classifier_kaggle.joblib',
                'url_classifier.joblib'
            ]
            url_model_path = None
            for name in preferred_url_models:
                candidate = self.models_path / name
                if candidate.exists():
                    url_model_path = candidate
                    break
            if url_model_path and url_model_path.exists():
                url_model_data = joblib.load(url_model_path)
                if isinstance(url_model_data, dict) and 'classifier' in url_model_data:
                    self.url_classifier = url_model_data['classifier']
                elif hasattr(url_model_data, 'predict'):
                    self.url_classifier = url_model_data
                else:
                    logger.warning("URL classifier model format not recognized")
            else:
                logger.warning("URL classifier model not found")

            content_model_path = self.models_path / 'content_analyzer_kaggle.joblib'
            if not content_model_path.exists():
                content_model_path = self.models_path / 'content_detector.joblib'
            if content_model_path.exists():
                content_model_data = joblib.load(content_model_path)
                if isinstance(content_model_data, dict) and 'classifier' in content_model_data:
                    self.content_detector = content_model_data['classifier']
                    if 'vectorizer' in content_model_data:
                        self._content_vectorizer = content_model_data['vectorizer']
                elif hasattr(content_model_data, 'predict'):
                    self.content_detector = content_model_data
                    vectorizer_path = self.models_path / 'content_vectorizer_kaggle.joblib'
                    if vectorizer_path.exists():
                        self._content_vectorizer = joblib.load(vectorizer_path)
            else:
                logger.warning("Content detector model not found")

            self.models_loaded = bool(self.url_classifier or self.content_detector)
            if not self.models_loaded:
                logger.warning("No disk models. Training fallback models in-memory...")
                self._train_fallback_models()
                self.models_loaded = bool(self.url_classifier or self.content_detector)
            return self.models_loaded
        except Exception as e:
            logger.warning(f"Failed to load persisted models ({e}); training fallbacks.")
            try:
                self._train_fallback_models()
                self.models_loaded = bool(self.url_classifier or self.content_detector)
                return self.models_loaded
            except Exception as inner_exc:
                logger.error(f"Failed to train fallback models: {inner_exc}")
                self.models_loaded = False
                return False

    def _train_fallback_models(self) -> None:
        try:
            urls, labels = generate_url_training_data()
        except Exception:
            benign = [
                "https://google.com","https://github.com","https://microsoft.com","https://apple.com",
                "https://stackoverflow.com","https://wikipedia.org","https://openai.com","https://linkedin.com",
                "https://cloudflare.com","https://python.org",
            ]
            malicious = [
                "http://192.168.1.1/login","https://paypal-secure-verify.ga","http://secure-bank-update123.tk",
                "https://microsoft-security-alert.cf","http://facebook-login-verify.tk","https://netflix-payment-update.ga",
                "http://apple-id-verify.ml","https://ebay-account-suspended.cf","http://10.0.0.5/admin?password=1",
                "http://phish.example.tk/verify?account=foo",
            ]
            urls = malicious + benign
            labels = [1] * len(malicious) + [0] * len(benign)
        clf = URLThreatClassifier()
        clf.train(urls, labels)
        self.url_classifier = clf.classifier

        try:
            contents, c_labels = generate_content_training_data()
        except Exception:
            contents = [
                "<html><body><h1>URGENT</h1><form><input type='password'></form></body></html>",
                "<html><body><p>Welcome</p></body></html>",
            ]
            c_labels = [1, 0]
        det = ContentPhishingDetector()
        det.train(contents, c_labels, content_type='html')
        self.content_detector = det.classifier

    def get_model_status(self) -> Dict[str, Any]:
        return {
            'url_classifier_trained': self.url_classifier is not None,
            'content_detector_trained': self.content_detector is not None,
            'models_loaded': self.models_loaded,
            'total_models': int(self.url_classifier is not None) + int(self.content_detector is not None)
        }

    def analyze_url_ml(self, url: str) -> Dict[str, Any]:
        try:
            if not self.models_loaded:
                return {'ml_enabled': False, 'prediction': 0, 'threat_probability': 0.0, 'detected_issues': ['ML disabled'], 'confidence': 0.0}
            features = None
            feature_df = None
            try:
                extractor = URLThreatClassifier()
                features_dict = extractor.extract_features(url)
                if hasattr(self.url_classifier, 'feature_names_in_'):
                    expected_cols = list(self.url_classifier.feature_names_in_)
                    feature_df = pd.DataFrame([[features_dict.get(col, 0) for col in expected_cols]], columns=expected_cols)
                else:
                    feature_df = pd.DataFrame([features_dict])
            except Exception as e:
                logger.warning(f"Feature DF build failed, using numeric fallback: {e}")
                features = self._extract_url_features(url)
                feature_df = features.reshape(1, -1)

            if self.url_classifier is not None:
                pred = self.url_classifier.predict(feature_df)[0]
                proba = self.url_classifier.predict_proba(feature_df)[0]
                threat_prob = proba[1] if len(proba) > 1 else 0.0
                if features is None:
                    try:
                        features = self._extract_url_features(url)
                    except Exception:
                        features = np.zeros(20, dtype=np.float32)
                issues = self._analyze_url_features(features, url)
                return {'ml_enabled': True, 'prediction': int(pred), 'threat_probability': float(threat_prob), 'detected_issues': issues, 'confidence': float(max(proba))}
            return self._rule_based_url_analysis(url)
        except Exception as e:
            logger.error(f"URL ML analysis failed: {e}")
            return {'ml_enabled': False, 'prediction': 0, 'threat_probability': 0.0, 'detected_issues': [f'Error: {e}'], 'confidence': 0.0}

    def analyze_content_ml(self, content: str) -> Dict[str, Any]:
        try:
            if not _BS4_AVAILABLE:
                return self._rule_based_content_analysis(content)
            if not self.models_loaded or not self.content_detector:
                return self._rule_based_content_analysis(content)
            if hasattr(self, '_content_vectorizer') and self._content_vectorizer and hasattr(self._content_vectorizer, 'vocabulary_'):
                features = self._content_vectorizer.transform([content])
                pred = self.content_detector.predict(features)[0]
                proba = self.content_detector.predict_proba(features)[0]
                phishing_prob = proba[1] if len(proba) > 1 else 0.0
                return {'ml_enabled': True, 'phishing_probability': float(phishing_prob), 'threat_detected': bool(pred), 'confidence': float(max(proba)), 'detected_issues': self._analyze_content_features_text(content)}
            features = self._extract_content_features(content)
            features_2d = features.reshape(1, -1)
            pred = self.content_detector.predict(features_2d)[0]
            proba = self.content_detector.predict_proba(features_2d)[0]
            phishing_prob = proba[1] if len(proba) > 1 else 0.0
            return {'ml_enabled': True, 'phishing_probability': float(phishing_prob), 'threat_detected': bool(pred), 'confidence': float(max(proba)), 'detected_issues': self._analyze_content_features(features, content)}
        except Exception as e:
            logger.error(f"Content ML analysis failed: {e}")
            return {'ml_enabled': False, 'phishing_probability': 0.0, 'threat_detected': False, 'confidence': 0.0, 'detected_issues': [f'Error: {e}']}

    def _extract_url_features(self, url: str) -> np.ndarray:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower() if parsed.netloc else ""
            path = parsed.path.lower()
            query = parsed.query.lower()
            features = []
            features.append(len(url))
            features.append(len(domain))
            features.append(len(path))
            features.append(len(query))
            features.append(len(domain.split('.')) - 1)
            features.append(1 if domain.startswith('www.') else 0)
            features.append(1 if re.search(r'\d', domain) else 0)
            features.append(path.count('/'))
            features.append(1 if '.php' in path or '.asp' in path else 0)
            features.append(1 if 'login' in path or 'signin' in path else 0)
            features.append(query.count('='))
            features.append(1 if 'password' in query or 'pwd' in query else 0)
            features.append(1 if 'redirect' in query or 'url' in query else 0)
            features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)
            features.append(1 if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0)
            arr = np.array(features, dtype=np.float32)
            expected = 20
            if len(arr) < expected:
                arr = np.pad(arr, (0, expected - len(arr)), 'constant')
            elif len(arr) > expected:
                arr = arr[:expected]
            return arr
        except Exception:
            return np.zeros(20, dtype=np.float32)

    def _extract_content_features(self, content: str) -> np.ndarray:
        try:
            content_lower = content.lower()
            feats = []
            feats.append(len(content))
            feats.append(len(content.split()))
            feats.append(len(content.split('\n')))
            for kw in ['password', 'login', 'signin', 'bank', 'paypal', 'credit', 'card', 'ssn', 'social']:
                feats.append(content_lower.count(kw))
            feats.append(content_lower.count('form'))
            feats.append(content_lower.count('input'))
            feats.append(content_lower.count('submit'))
            feats.append(content_lower.count('http://'))
            feats.append(content_lower.count('https://'))
            arr = np.array(feats, dtype=np.float32)
            expected = 20
            if len(arr) < expected:
                arr = np.pad(arr, (0, expected - len(arr)), 'constant')
            elif len(arr) > expected:
                arr = arr[:expected]
            return arr
        except Exception:
            return np.zeros(20, dtype=np.float32)

    def _analyze_url_features(self, features: np.ndarray, url: str) -> List[str]:
        issues = []
        try:
            if features[0] > 100:
                issues.append("Suspiciously long URL")
            if features[4] > 3:
                issues.append("Multiple subdomains")
            if features[6] > 0:
                issues.append("Numbers in domain name")
            if features[8] > 0:
                issues.append("Suspicious file extensions")
            if features[10] > 0:
                issues.append("Multiple query parameters")
            if features[11] > 0:
                issues.append("Password in URL parameters")
            if features[12] > 0:
                issues.append("Redirect parameters")
            if features[13] > 0:
                issues.append("IP address in domain")
            if features[14] > 0:
                issues.append("Suspicious top-level domain")
        except Exception:
            issues.append("Feature analysis error")
        return issues or ["No suspicious patterns detected"]

    def _analyze_content_features(self, features: np.ndarray, content: str) -> List[str]:
        issues = []
        try:
            if features[0] > 10000:
                issues.append("Unusually long content")
            if features[3] > 5:
                issues.append("Multiple password references")
            if features[4] > 3:
                issues.append("Multiple login references")
            if features[5] > 2:
                issues.append("Banking/financial references")
            if features[6] > 2:
                issues.append("Credit card references")
            if features[7] > 2:
                issues.append("Social Security Number references")
            if features[8] > 0:
                issues.append("Form elements detected")
            if features[9] > 0:
                issues.append("Input fields detected")
            if features[10] > 0:
                issues.append("Submit buttons detected")
            if features[11] > 5:
                issues.append("Multiple external links")
        except Exception:
            issues.append("Feature analysis error")
        return issues or ["No suspicious patterns detected"]

    def _analyze_content_features_text(self, content: str) -> List[str]:
        issues = []
        try:
            content_lower = content.lower()
            for kw in ['password','login','signin','account','verify','confirm','bank','credit','card','ssn','social security','paypal','urgent','immediate','suspended','locked','verify now','update','security','fraud','suspicious','unusual']:
                if kw in content_lower:
                    issues.append(f"Contains suspicious keyword: {kw}")
            if '<form' in content_lower:
                issues.append("Contains HTML form")
            if '<input' in content_lower:
                issues.append("Contains input fields")
            if 'http://' in content_lower or 'https://' in content_lower:
                issues.append("Contains external links")
            for word in ['urgent','immediate','now','asap','critical','emergency']:
                if word in content_lower:
                    issues.append(f"Contains urgency indicator: {word}")
        except Exception:
            issues.append("Feature analysis error")
        return issues or ["No suspicious patterns detected"]


_ml_engine = None
_ml_engine_lock = threading.Lock()

def get_ml_engine() -> MLSecurityEngine:
    global _ml_engine
    if _ml_engine is None:
        with _ml_engine_lock:
            if _ml_engine is None:
                _ml_engine = MLSecurityEngine(load_models=True)
    return _ml_engine

"""
ML Integration Module for WebShield
Provides unified interface for all ML models
"""

import os
import logging
import joblib
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import re
from .url_classifier import URLThreatClassifier  # Fallback training
from .url_classifier import generate_training_data as generate_url_training_data
from .content_analyzer import ContentPhishingDetector  # Fallback training
from .content_analyzer import generate_content_training_data
try:
    from bs4 import BeautifulSoup  # noqa: F401
    _BS4_AVAILABLE = True
except Exception:
    _BS4_AVAILABLE = False

logger = logging.getLogger(__name__)

class MLSecurityEngine:
    """Main ML Security Engine that integrates all ML models"""
    
    def __init__(self, load_models: bool = True):
        self.models_loaded = False
        self.url_classifier = None
        self.content_detector = None
        self._content_vectorizer = None
        self.models_path = Path(__file__).parent / 'saved_models'
        
        if load_models:
            self.load_models()
    
    def load_models(self) -> bool:
        """Load all trained ML models"""
        try:
            logger.info("Loading ML models...")
            
            # Load URL classifier (prefer enhanced Kaggle-trained models)
            preferred_url_models = [
                'enhanced_url_classifier_rf_kaggle.joblib',
                'enhanced_url_classifier_gb_kaggle.joblib',
                'url_classifier_kaggle.joblib',
                'url_classifier.joblib'
            ]
            url_model_path = None
            for name in preferred_url_models:
                candidate = self.models_path / name
                if candidate.exists():
                    url_model_path = candidate
                    break
            if url_model_path.exists():
                url_model_data = joblib.load(url_model_path)
                # Handle both direct models and dictionary-wrapped models
                if isinstance(url_model_data, dict) and 'classifier' in url_model_data:
                    self.url_classifier = url_model_data['classifier']
                    logger.info("URL classifier loaded successfully (from dict)")
                elif hasattr(url_model_data, 'predict'):
                    self.url_classifier = url_model_data
                    logger.info(f"URL classifier loaded successfully from {url_model_path.name}")
                else:
                    logger.warning("URL classifier model format not recognized")
            else:
                logger.warning("URL classifier model not found")
            
            # Load content detector (prefer Kaggle-trained models)
            content_model_path = self.models_path / 'content_analyzer_kaggle.joblib'
            if not content_model_path.exists():
                content_model_path = self.models_path / 'content_detector.joblib'
            if content_model_path.exists():
                content_model_data = joblib.load(content_model_path)
                # Handle both direct models and dictionary-wrapped models
                if isinstance(content_model_data, dict) and 'classifier' in content_model_data:
                    self.content_detector = content_model_data['classifier']
                    # Also load the vectorizer if available
                    if 'vectorizer' in content_model_data:
                        self._content_vectorizer = content_model_data['vectorizer']
                        logger.info("Content detector and vectorizer loaded successfully (from dict)")
                    else:
                        logger.info("Content detector loaded successfully (from dict), no vectorizer")
                elif hasattr(content_model_data, 'predict'):
                    self.content_detector = content_model_data
                    logger.info("Content detector loaded successfully (direct model)")
                    
                    # Try to load vectorizer separately for Kaggle models
                    vectorizer_path = self.models_path / 'content_vectorizer_kaggle.joblib'
                    if vectorizer_path.exists():
                        self._content_vectorizer = joblib.load(vectorizer_path)
                        logger.info("Content vectorizer loaded successfully (separate file)")
                    else:
                        logger.info("No separate vectorizer found")
                else:
                    logger.warning("Content detector model format not recognized")
            else:
                logger.warning("Content detector model not found")
            
            self.models_loaded = bool(self.url_classifier or self.content_detector)
            if not self.models_loaded:
                logger.warning("No ML models loaded from disk. Training lightweight fallback models...")
                self._train_fallback_models()
                self.models_loaded = bool(self.url_classifier or self.content_detector)
            logger.info(f"ML models loaded: {self.models_loaded}")
            return self.models_loaded
            
        except Exception as e:
            logger.warning(f"Failed to load persisted ML models ({e}). Training lightweight fallback models in-memory.")
            # Attempt to build fallback models in runtime (handles pickle incompatibilities)
            try:
                self._train_fallback_models()
                self.models_loaded = bool(self.url_classifier or self.content_detector)
                logger.info(f"Fallback models trained: {self.models_loaded}")
                return self.models_loaded
            except Exception as inner_exc:
                logger.error(f"Failed to train fallback models: {inner_exc}")
                self.models_loaded = False
                return False

    def _train_fallback_models(self) -> None:
        """Train minimal ML models to use when saved models cannot be loaded."""
        # Train URL classifier on synthetic data
        try:
            urls, labels = generate_url_training_data()
        except Exception:
            # Backup synthetic dataset with enough samples per class for stratification
            benign = [
                "https://google.com",
                "https://github.com",
                "https://microsoft.com",
                "https://apple.com",
                "https://stackoverflow.com",
                "https://wikipedia.org",
                "https://openai.com",
                "https://linkedin.com",
                "https://cloudflare.com",
                "https://python.org",
            ]
            malicious = [
                "http://192.168.1.1/login",
                "https://paypal-secure-verify.ga",
                "http://secure-bank-update123.tk",
                "https://microsoft-security-alert.cf",
                "http://facebook-login-verify.tk",
                "https://netflix-payment-update.ga",
                "http://apple-id-verify.ml",
                "https://ebay-account-suspended.cf",
                "http://10.0.0.5/admin?password=1",
                "http://phish.example.tk/verify?account=foo",
            ]
            urls = malicious + benign
            labels = [1] * len(malicious) + [0] * len(benign)
        try:
            url_model = URLThreatClassifier()
            url_model.train(urls, labels)
            # Use the trained sklearn estimator directly for prediction interface in this engine
            self.url_classifier = url_model.classifier
            logger.info("Fallback URL classifier trained in runtime")
        except Exception as e:
            logger.warning(f"Failed to train fallback URL classifier: {e}")
            self.url_classifier = None

        # Train content detector on synthetic HTML samples
        try:
            contents, c_labels = generate_content_training_data()
        except Exception:
            # Backup synthetic dataset with enough samples per class
            phishing_samples = [
                "<html><body><h1>URGENT</h1><p>Verify now</p><form><input type='password'></form></body></html>",
                "<html><body><p>Your account is suspended. Update password immediately!</p></body></html>",
                "<html><body><p>Security alert: confirm credentials</p><a href='http://bit.ly/x'>link</a></body></html>",
                "<html><body><form action='http://malicious'>input</form></body></html>",
                "<html><body><p>Limited time verification required</p></body></html>",
            ]
            legit_samples = [
                "<html><body><h1>Welcome</h1><p>Thank you for visiting.</p></body></html>",
                "<html><body><h1>Docs</h1><p>Read the documentation.</p></body></html>",
                "<html><body><p>Regular news article content with links to https://example.com</p></body></html>",
                "<html><body><p>Contact us at support@example.com</p></body></html>",
                "<html><body><p>Account settings page</p></body></html>",
            ]
            contents = phishing_samples + legit_samples
            c_labels = [1] * len(phishing_samples) + [0] * len(legit_samples)
        try:
            content_model = ContentPhishingDetector()
            content_model.train(contents, c_labels, content_type='html')
            # Prefer numeric-feature model usage; vectorizer is not required by our analysis path
            self.content_detector = content_model.classifier
            # No vectorizer needed for numeric features path
            logger.info("Fallback content detector trained in runtime")
        except Exception as e:
            logger.warning(f"Failed to train fallback content detector: {e}")
            self.content_detector = None
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of all ML models"""
        return {
            'url_classifier_trained': self.url_classifier is not None,
            'content_detector_trained': self.content_detector is not None,
            'models_loaded': self.models_loaded,
            'total_models': sum([1 for m in [self.url_classifier, self.content_detector] if m is not None])
        }
    
    def analyze_url_ml(self, url: str) -> Dict[str, Any]:
        """Analyze URL using ML models"""
        try:
            if not self.models_loaded:
                return {
                    'ml_enabled': False,
                    'prediction': 0,
                    'threat_probability': 0.0,
                    'detected_issues': ['ML models not loaded'],
                    'confidence': 0.0
                }
            
            # Extract features from URL using the same schema as training
            # Prefer feature names from the trained model to avoid mismatches
            features = None
            feature_df = None
            try:
                from .url_classifier import URLThreatClassifier
                feature_extractor = URLThreatClassifier()
                features_dict = feature_extractor.extract_features(url)
                if hasattr(self.url_classifier, 'feature_names_in_'):
                    expected_cols = list(self.url_classifier.feature_names_in_)
                    # Build DataFrame with correct column order and fill missing with 0
                    feature_df = pd.DataFrame([[features_dict.get(col, 0) for col in expected_cols]], columns=expected_cols)
                else:
                    # Fallback: single-row DataFrame from dict (order may vary)
                    feature_df = pd.DataFrame([features_dict])
            except Exception as e:
                logger.warning(f"Fallback to numerical feature extractor due to error: {e}")
                # Fallback to numeric features array
                features = self._extract_url_features(url)
                feature_df = features.reshape(1, -1)
            
            # Make prediction if URL classifier is available
            if self.url_classifier:
                try:
                    prediction = self.url_classifier.predict(feature_df)[0]
                    probability = self.url_classifier.predict_proba(feature_df)[0]
                    threat_prob = probability[1] if len(probability) > 1 else 0.0
                    
                    # Determine detected issues based on features
                    # Ensure we always have a numeric feature array for issue analysis
                    if features is None:
                        try:
                            features = self._extract_url_features(url)
                        except Exception:
                            features = np.zeros(20, dtype=np.float32)
                    detected_issues = self._analyze_url_features(features, url)
                    
                    return {
                        'ml_enabled': True,
                        'prediction': int(prediction),
                        'threat_probability': float(threat_prob),
                        'detected_issues': detected_issues,
                        'confidence': float(max(probability))
                    }
                except Exception as e:
                    logger.warning(f"URL classifier prediction failed: {e}")
                    return self._rule_based_url_analysis(url)
            else:
                return self._rule_based_url_analysis(url)
                
        except Exception as e:
            logger.error(f"URL ML analysis failed: {e}")
            return {
                'ml_enabled': False,
                'prediction': 0,
                'threat_probability': 0.0,
                'detected_issues': [f'Analysis error: {str(e)}'],
                'confidence': 0.0
            }
    
    def analyze_content_ml(self, content: str) -> Dict[str, Any]:
        """Analyze content using ML models"""
        try:
            # If BeautifulSoup not available, skip heavy text pipelines gracefully
            if not _BS4_AVAILABLE:
                return self._rule_based_content_analysis(content)
            if not self.models_loaded or not self.content_detector:
                return self._rule_based_content_analysis(content)
            
            # Check if we have the vectorizer (for TfidfVectorizer-based models)
            if hasattr(self, '_content_vectorizer') and self._content_vectorizer:
                # Check if the vectorizer is fitted
                if hasattr(self._content_vectorizer, 'vocabulary_'):
                    # Use TfidfVectorizer for text features
                    try:
                        # Vectorize the text content
                        features = self._content_vectorizer.transform([content])
                        prediction = self.content_detector.predict(features)[0]
                        probability = self.content_detector.predict_proba(features)[0]
                        phishing_prob = probability[1] if len(probability) > 1 else 0.0
                        
                        return {
                            'ml_enabled': True,
                            'phishing_probability': float(phishing_prob),
                            'threat_detected': bool(prediction),
                            'confidence': float(max(probability)),
                            'detected_issues': self._analyze_content_features_text(content)
                        }
                    except Exception as e:
                        logger.warning(f"Content detector prediction failed: {e}")
                        return self._rule_based_content_analysis(content)
                else:
                    logger.warning("Content vectorizer is not fitted, falling back to rule-based analysis")
                    return self._rule_based_content_analysis(content)
            else:
                # Fallback to numerical features if no vectorizer
                features = self._extract_content_features(content)
                try:
                    features_2d = features.reshape(1, -1)
                    prediction = self.content_detector.predict(features_2d)[0]
                    probability = self.content_detector.predict_proba(features_2d)[0]
                    phishing_prob = probability[1] if len(probability) > 1 else 0.0
                    
                    return {
                        'ml_enabled': True,
                        'phishing_probability': float(phishing_prob),
                        'threat_detected': bool(prediction),
                        'confidence': float(max(probability)),
                        'detected_issues': self._analyze_content_features(features, content)
                    }
                except Exception as e:
                    logger.warning(f"Content detector prediction failed: {e}")
                    return self._rule_based_content_analysis(content)
                
        except Exception as e:
            logger.error(f"Content ML analysis failed: {e}")
            return {
                'ml_enabled': False,
                'phishing_probability': 0.0,
                'threat_detected': False,
                'confidence': 0.0,
                'detected_issues': [f'Analysis error: {str(e)}']
            }
    
    def _extract_url_features(self, url: str) -> np.ndarray:
        """Extract numerical features from URL"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower() if parsed.netloc else ""
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            features = []
            
            # URL length features
            features.append(len(url))
            features.append(len(domain))
            features.append(len(path))
            features.append(len(query))
            
            # Domain features
            features.append(len(domain.split('.')) - 1)  # Subdomain count
            features.append(1 if domain.startswith('www.') else 0)
            features.append(1 if re.search(r'\d', domain) else 0)
            
            # Path features
            features.append(path.count('/'))
            features.append(1 if '.php' in path or '.asp' in path else 0)
            features.append(1 if 'login' in path or 'signin' in path else 0)
            
            # Query features
            features.append(query.count('='))
            features.append(1 if 'password' in query or 'pwd' in query else 0)
            features.append(1 if 'redirect' in query or 'url' in query else 0)
            
            # Suspicious patterns
            features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  # IP address
            features.append(1 if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0)
            
            # Convert to numpy array and pad/truncate to expected length
            features = np.array(features, dtype=np.float32)
            
            # Pad or truncate to expected feature count (adjust based on your model)
            expected_features = 20
            if len(features) < expected_features:
                features = np.pad(features, (0, expected_features - len(features)), 'constant')
            elif len(features) > expected_features:
                features = features[:expected_features]
            
            return features
                
        except Exception as e:
            logger.error(f"URL feature extraction failed: {e}")
            # Return zero features on error
            return np.zeros(20, dtype=np.float32)
    
    def _extract_content_features(self, content: str) -> np.ndarray:
        """Extract numerical features from content"""
        try:
            content_lower = content.lower()
            
            features = []
            
            # Content length features
            features.append(len(content))
            features.append(len(content.split()))
            features.append(len(content.split('\n')))
            
            # Suspicious keywords
            suspicious_keywords = ['password', 'login', 'signin', 'bank', 'paypal', 'credit', 'card', 'ssn', 'social']
            for keyword in suspicious_keywords:
                features.append(content_lower.count(keyword))
            
            # Form indicators
            features.append(content_lower.count('form'))
            features.append(content_lower.count('input'))
            features.append(content_lower.count('submit'))
            
            # External links
            features.append(content_lower.count('http://'))
            features.append(content_lower.count('https://'))
            
            # Convert to numpy array and pad/truncate
            features = np.array(features, dtype=np.float32)
            
            expected_features = 20
            if len(features) < expected_features:
                features = np.pad(features, (0, expected_features - len(features)), 'constant')
            elif len(features) > expected_features:
                features = features[:expected_features]
            
            return features
                
        except Exception as e:
            logger.error(f"Content feature extraction failed: {e}")
            # Return zero features on error
            return np.zeros(20, dtype=np.float32)
    
    def _analyze_url_features(self, features: np.ndarray, url: str) -> List[str]:
        """Analyze URL features to determine suspicious patterns"""
        issues = []
        
        try:
            # Check for suspicious patterns based on features
            if features[0] > 100:  # Long URL
                issues.append("Suspiciously long URL")
            
            if features[4] > 3:  # Many subdomains
                issues.append("Multiple subdomains")
            
            if features[6] > 0:  # Numbers in domain
                issues.append("Numbers in domain name")
            
            if features[8] > 0:  # Suspicious file extensions
                issues.append("Suspicious file extensions")
            
            if features[10] > 0:  # Many query parameters
                issues.append("Multiple query parameters")
            
            if features[11] > 0:  # Password in query
                issues.append("Password in URL parameters")
            
            if features[12] > 0:  # Redirect in query
                issues.append("Redirect parameters")
            
            if features[13] > 0:  # IP address in domain
                issues.append("IP address in domain")
            
            if features[14] > 0:  # Suspicious TLDs
                issues.append("Suspicious top-level domain")
                
        except Exception as e:
            logger.warning(f"URL feature analysis failed: {e}")
            issues.append("Feature analysis error")
        
        return issues if issues else ["No suspicious patterns detected"]
    
    def _analyze_content_features(self, features: np.ndarray, content: str) -> List[str]:
        """Analyze content features to determine suspicious patterns"""
        issues = []
        
        try:
            # Check for suspicious patterns based on features
            if features[0] > 10000:  # Very long content
                issues.append("Unusually long content")
            
            # Check for suspicious keywords
            if features[3] > 5:  # Many password references
                issues.append("Multiple password references")
            
            if features[4] > 3:  # Many login references
                issues.append("Multiple login references")
            
            if features[5] > 2:  # Banking references
                issues.append("Banking/financial references")
            
            if features[6] > 2:  # Credit card references
                issues.append("Credit card references")
            
            if features[7] > 2:  # SSN references
                issues.append("Social Security Number references")
            
            if features[8] > 0:  # Form indicators
                issues.append("Form elements detected")
            
            if features[9] > 0:  # Input fields
                issues.append("Input fields detected")
            
            if features[10] > 0:  # Submit buttons
                issues.append("Submit buttons detected")
            
            if features[11] > 5:  # Many external links
                issues.append("Multiple external links")
                
        except Exception as e:
            logger.warning(f"Content feature analysis failed: {e}")
            issues.append("Feature analysis error")
        
        return issues if issues else ["No suspicious patterns detected"]
    
    def _analyze_content_features_text(self, content: str) -> List[str]:
        """Analyze text content features for TfidfVectorizer-based models"""
        issues = []
        
        try:
            content_lower = content.lower()
            
            # Check for suspicious keywords
            suspicious_keywords = [
                'password', 'login', 'signin', 'account', 'verify', 'confirm',
                'bank', 'credit', 'card', 'ssn', 'social security', 'paypal',
                'urgent', 'immediate', 'suspended', 'locked', 'verify now',
                'update', 'security', 'fraud', 'suspicious', 'unusual'
            ]
            
            for keyword in suspicious_keywords:
                if keyword in content_lower:
                    issues.append(f"Contains suspicious keyword: {keyword}")
            
            # Check for form elements
            if '<form' in content_lower:
                issues.append("Contains HTML form")
            
            if '<input' in content_lower:
                issues.append("Contains input fields")
            
            # Check for external links
            if 'http://' in content_lower or 'https://' in content_lower:
                issues.append("Contains external links")
            
            # Check for urgency indicators
            urgency_words = ['urgent', 'immediate', 'now', 'asap', 'critical', 'emergency']
            for word in urgency_words:
                if word in content_lower:
                    issues.append(f"Contains urgency indicator: {word}")
                    
        except Exception as e:
            logger.warning(f"Text content feature analysis failed: {e}")
            issues.append("Feature analysis error")
        
        return issues if issues else ["No suspicious patterns detected"]
    
    def _rule_based_url_analysis(self, url: str) -> Dict[str, Any]:
        """Fallback rule-based URL analysis"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower() if parsed.netloc else ""
            
            # Basic rule-based checks
            suspicious_score = 0
            detected_issues = []
            
            # Check domain length
            if len(domain) > 50:
                suspicious_score += 20
                detected_issues.append("Very long domain name")
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
            if any(tld in domain for tld in suspicious_tlds):
                suspicious_score += 30
                detected_issues.append("Suspicious top-level domain")
            
            # Check for IP addresses
            if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
                suspicious_score += 25
                detected_issues.append("IP address in domain")
            
            # Check for numbers in domain
            if re.search(r'\d', domain):
                suspicious_score += 15
                detected_issues.append("Numbers in domain name")
            
            # Check for many subdomains
            if domain.count('.') > 2:
                suspicious_score += 20
                detected_issues.append("Multiple subdomains")
            
            return {
                'ml_enabled': False,
                'prediction': 1 if suspicious_score > 50 else 0,
                'threat_probability': min(suspicious_score / 100.0, 1.0),
                'detected_issues': detected_issues if detected_issues else ["No suspicious patterns"],
                'confidence': 0.7 if suspicious_score > 30 else 0.3,
                'suspicious_score': suspicious_score
            }
            
        except Exception as e:
            logger.error(f"Rule-based URL analysis failed: {e}")
            return {
                'ml_enabled': False,
                'prediction': 0,
                'threat_probability': 0.0,
                'detected_issues': ["Analysis error"],
                'confidence': 0.0,
                'suspicious_score': 0
            }
    
    def _rule_based_content_analysis(self, content: str) -> Dict[str, Any]:
        """Fallback rule-based content analysis"""
        try:
            content_lower = content.lower()
            
            # Basic rule-based checks
            phishing_score = 0
            detected_issues = []
            
            # Check for suspicious keywords
            suspicious_keywords = {
                'password': 20,
                'login': 15,
                'signin': 15,
                'bank': 25,
                'paypal': 25,
                'credit': 20,
                'card': 20,
                'ssn': 30,
                'social': 15
            }
            
            for keyword, score in suspicious_keywords.items():
                if keyword in content_lower:
                    phishing_score += score
                    detected_issues.append(f"Contains '{keyword}'")
            
            # Check for form elements
            if 'form' in content_lower:
                phishing_score += 20
                detected_issues.append("Form elements detected")
            
            if 'input' in content_lower:
                phishing_score += 15
                detected_issues.append("Input fields detected")
            
            # Check for external links
            if content_lower.count('http://') > 5:
                phishing_score += 15
                detected_issues.append("Many external links")
            
            return {
                'ml_enabled': False,
                'phishing_probability': min(phishing_score / 100.0, 1.0),
                'threat_detected': phishing_score > 50,
                'confidence': 0.6 if phishing_score > 30 else 0.4,
                'detected_issues': detected_issues if detected_issues else ["No suspicious patterns"],
                'phishing_score': phishing_score
            }
            
        except Exception as e:
            logger.error(f"Rule-based content analysis failed: {e}")
            return {
                'ml_enabled': False,
                'phishing_probability': 0.0,
                'threat_detected': False,
                'confidence': 0.0,
                'detected_issues': ["Analysis error"],
                'phishing_score': 0
            }

# Global ML engine instance
_ml_engine = None
_ml_engine_lock = threading.Lock()

def get_ml_engine() -> MLSecurityEngine:
    """Get or create global ML engine instance"""
    global _ml_engine
    
    if _ml_engine is None:
        with _ml_engine_lock:
            if _ml_engine is None:
                _ml_engine = MLSecurityEngine(load_models=True)
    
    return _ml_engine
