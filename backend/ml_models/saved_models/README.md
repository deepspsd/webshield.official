# Machine Learning Models

This directory contains trained machine learning models for WebShield's threat detection system.

## Note: Model Files Not Included

Due to the large size of the trained model files (several MB each), they are not included in this repository. The models include:

- `content_analyzer_kaggle.joblib` - Content analysis model trained on Kaggle dataset
- `content_detector.joblib` - Content detection model
- `content_vectorizer_kaggle.joblib` - TF-IDF vectorizer for content analysis
- `enhanced_url_classifier_rf_kaggle.joblib` - Enhanced Random Forest URL classifier
- `url_classifier.joblib` - Base URL classification model
- `url_classifier_enhanced.joblib` - Enhanced URL classifier
- `url_classifier_kaggle.joblib` - URL classifier trained on Kaggle dataset
- `url_classifier_optimized.joblib` - Optimized URL classifier

## How to Train Models

To generate these model files, run the training scripts:

```bash
# Train content analysis model
python backend/ml_models/content_analyzer.py

# Train URL classifier
python backend/ml_models/url_classifier.py

# Train with Kaggle dataset
python backend/ml_models/train_with_kaggle_dataset.py
```

## Model Information

These models are trained using scikit-learn and provide:
- Phishing website detection
- Malicious URL classification
- Content-based threat analysis
- Brand impersonation detection

The models achieve high accuracy on various threat datasets and are regularly updated with new training data.
