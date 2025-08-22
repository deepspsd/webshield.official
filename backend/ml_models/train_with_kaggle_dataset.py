#!/usr/bin/env python3
"""
Train ML Models with Kaggle Malicious URLs Dataset
This script trains both URL classifier and content analyzer using the comprehensive dataset
"""

import sys
import os
import pandas as pd
import numpy as np
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
import time
import re
import urllib.parse
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import warnings
warnings.filterwarnings('ignore')

# Use absolute imports for running directly
try:
    from backend.ml_models.url_classifier import URLThreatClassifier
    from backend.ml_models.content_analyzer import ContentPhishingDetector
except ImportError:
    # Fallback for direct execution
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from url_classifier import URLThreatClassifier
    from content_analyzer import ContentPhishingDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class KaggleDatasetTrainer:
    """Trainer class for using Kaggle malicious URLs dataset"""
    
    def __init__(self, dataset_path: str = "malicious_phish.csv"):
        # Handle relative paths - if the file doesn't exist in current dir, 
        # try to find it relative to the script location
        if not os.path.exists(dataset_path):
            script_dir = Path(__file__).parent
            potential_path = script_dir / dataset_path
            if potential_path.exists():
                self.dataset_path = str(potential_path)
                logger.info(f"Found dataset at: {self.dataset_path}")
            else:
                self.dataset_path = dataset_path
        else:
            self.dataset_path = dataset_path
            
        self.data = None
        self.url_classifier = URLThreatClassifier()
        self.content_analyzer = ContentPhishingDetector()
        
    def load_and_preprocess_data(self):
        """Load and preprocess the Kaggle dataset"""
        logger.info("Loading Kaggle dataset...")
        
        try:
            # Load the CSV file
            self.data = pd.read_csv(self.dataset_path)
            logger.info(f"Loaded {len(self.data)} URLs from dataset")
            
            # Display basic info
            logger.info(f"Dataset columns: {list(self.data.columns)}")
            logger.info(f"Dataset shape: {self.data.shape}")
            
            # Check for missing values
            missing_values = self.data.isnull().sum()
            logger.info(f"Missing values:\n{missing_values}")
            
            # Display class distribution
            if 'type' in self.data.columns:
                class_distribution = self.data['type'].value_counts()
                logger.info(f"Class distribution:\n{class_distribution}")
                
                # Map classes to binary (malicious vs benign)
                self.data['is_malicious'] = self.data['type'].map({
                    'benign': 0,
                    'phishing': 1,
                    'defacement': 1,
                    'malware': 1
                })
                
                # Handle any unknown classes
                self.data['is_malicious'] = self.data['is_malicious'].fillna(1)  # Default to malicious
                
                logger.info(f"Binary classification distribution:\n{self.data['is_malicious'].value_counts()}")
            
            # Clean URLs
            self.data['url_clean'] = self.data['url'].apply(self._clean_url)
            
            # Remove rows with invalid URLs
            valid_urls = self.data['url_clean'].notna()
            self.data = self.data[valid_urls].reset_index(drop=True)
            
            logger.info(f"After cleaning: {len(self.data)} valid URLs")
            
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            raise
    
    def _clean_url(self, url: str) -> str:
        """Clean and validate URL"""
        try:
            if pd.isna(url) or not isinstance(url, str):
                return None
                
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            # Parse URL to validate
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                return None
                
            return url
        except:
            return None
    
    def train_url_classifier(self):
        """Train the URL classifier with enhanced features"""
        logger.info("Training URL classifier...")
        
        try:
            # Extract features for all URLs
            logger.info("Extracting URL features...")
            feature_data = []
            labels = []
            
            for idx, row in self.data.iterrows():
                if idx % 10000 == 0:
                    logger.info(f"Processing URL {idx}/{len(self.data)}")
                
                try:
                    features = self.url_classifier.extract_features(row['url_clean'])
                    feature_data.append(features)
                    labels.append(row['is_malicious'])
                except Exception as e:
                    logger.warning(f"Error processing URL {idx}: {e}")
                    continue
            
            # Convert to DataFrame
            feature_df = pd.DataFrame(feature_data)
            labels = np.array(labels)
            
            logger.info(f"Feature matrix shape: {feature_df.shape}")
            logger.info(f"Labels shape: {labels.shape}")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                feature_df, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            logger.info(f"Training set: {X_train.shape[0]} samples")
            logger.info(f"Test set: {X_test.shape[0]} samples")
            
            # Train the classifier
            logger.info("Training Random Forest classifier...")
            self.url_classifier.classifier.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.url_classifier.classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"URL Classifier Accuracy: {accuracy:.4f}")
            logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
            
            # Cross-validation
            cv_scores = cross_val_score(self.url_classifier.classifier, X_train, y_train, cv=5)
            logger.info(f"Cross-validation scores: {cv_scores}")
            logger.info(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            # Save the trained model
            model_path = Path(__file__).parent / "saved_models" / "url_classifier_kaggle.joblib"
            model_path.parent.mkdir(exist_ok=True)
            joblib.dump(self.url_classifier.classifier, model_path)
            logger.info(f"URL classifier saved to {model_path}")
            
            self.url_classifier.is_trained = True
            
        except Exception as e:
            logger.error(f"Error training URL classifier: {e}")
            raise
    
    def train_content_analyzer(self):
        """Train the content analyzer with text features"""
        logger.info("Training content analyzer...")
        
        try:
            # For content analysis, we'll use URL text features since we don't have actual content
            # We'll create synthetic content features based on URL patterns
            
            logger.info("Creating synthetic content features...")
            
            # Extract text features from URLs
            url_texts = []
            labels = []
            
            for idx, row in self.data.iterrows():
                if idx % 10000 == 0:
                    logger.info(f"Processing content features for URL {idx}/{len(self.data)}")
                
                try:
                    # Create synthetic content based on URL
                    url_text = row['url_clean'].lower()
                    
                    # Extract domain and path for text analysis
                    parsed = urllib.parse.urlparse(url_text)
                    domain_text = parsed.netloc.replace('.', ' ')
                    path_text = parsed.path.replace('/', ' ').replace('-', ' ').replace('_', ' ')
                    
                    # Combine text features
                    combined_text = f"{domain_text} {path_text} {parsed.query}"
                    
                    url_texts.append(combined_text)
                    labels.append(row['is_malicious'])
                    
                except Exception as e:
                    logger.warning(f"Error processing content for URL {idx}: {e}")
                    continue
            
            # Vectorize text features
            logger.info("Vectorizing text features...")
            vectorizer = TfidfVectorizer(
                max_features=2000,
                ngram_range=(1, 3),
                min_df=5,
                max_df=0.8
            )
            
            X_text = vectorizer.fit_transform(url_texts)
            labels = np.array(labels)
            
            logger.info(f"Text feature matrix shape: {X_text.shape}")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_text, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Train content analyzer
            logger.info("Training content analyzer...")
            self.content_analyzer.classifier.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.content_analyzer.classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            logger.info(f"Content Analyzer Accuracy: {accuracy:.4f}")
            logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")
            
            # Save the trained model and vectorizer
            model_dir = Path(__file__).parent / "saved_models"
            model_dir.mkdir(exist_ok=True)
            
            content_model_path = model_dir / "content_analyzer_kaggle.joblib"
            vectorizer_path = model_dir / "content_vectorizer_kaggle.joblib"
            
            joblib.dump(self.content_analyzer.classifier, content_model_path)
            joblib.dump(vectorizer, vectorizer_path)
            
            logger.info(f"Content analyzer saved to {content_model_path}")
            logger.info(f"Vectorizer saved to {vectorizer_path}")
            
            self.content_analyzer.is_trained = True
            
        except Exception as e:
            logger.error(f"Error training content analyzer: {e}")
            raise
    
    def train_enhanced_models(self):
        """Train enhanced models with hyperparameter tuning"""
        logger.info("Training enhanced models with hyperparameter tuning...")
        
        try:
            # Enhanced URL classifier with GridSearch
            logger.info("Training enhanced URL classifier...")
            
            # Extract features
            feature_data = []
            labels = []
            
            for idx, row in self.data.iterrows():
                if idx % 20000 == 0:
                    logger.info(f"Processing enhanced features for URL {idx}/{len(self.data)}")
                
                try:
                    features = self.url_classifier.extract_features(row['url_clean'])
                    feature_data.append(features)
                    labels.append(row['is_malicious'])
                except Exception as e:
                    continue
            
            feature_df = pd.DataFrame(feature_data)
            labels = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                feature_df, labels, test_size=0.2, random_state=42, stratify=labels
            )
            
            # Grid search for Random Forest
            rf_param_grid = {
                'n_estimators': [100, 200, 300],
                'max_depth': [10, 20, None],
                'min_samples_split': [2, 5, 10],
                'min_samples_leaf': [1, 2, 4]
            }
            
            logger.info("Performing GridSearch for Random Forest...")
            rf_grid = GridSearchCV(
                RandomForestClassifier(random_state=42),
                rf_param_grid,
                cv=3,
                n_jobs=-1,
                verbose=1
            )
            
            rf_grid.fit(X_train, y_train)
            
            logger.info(f"Best Random Forest parameters: {rf_grid.best_params_}")
            logger.info(f"Best Random Forest score: {rf_grid.best_score_:.4f}")
            
            # Grid search for Gradient Boosting
            gb_param_grid = {
                'n_estimators': [100, 200],
                'learning_rate': [0.1, 0.2],
                'max_depth': [3, 5, 7]
            }
            
            logger.info("Performing GridSearch for Gradient Boosting...")
            gb_grid = GridSearchCV(
                GradientBoostingClassifier(random_state=42),
                gb_param_grid,
                cv=3,
                n_jobs=-1,
                verbose=1
            )
            
            gb_grid.fit(X_train, y_train)
            
            logger.info(f"Best Gradient Boosting parameters: {gb_grid.best_params_}")
            logger.info(f"Best Gradient Boosting score: {gb_grid.best_score_:.4f}")
            
            # Compare models
            rf_score = rf_grid.score(X_test, y_test)
            gb_score = gb_grid.score(X_test, y_test)
            
            logger.info(f"Random Forest test accuracy: {rf_score:.4f}")
            logger.info(f"Gradient Boosting test accuracy: {gb_score:.4f}")
            
            # Save the best model
            if rf_score >= gb_score:
                best_model = rf_grid.best_estimator_
                model_name = "enhanced_url_classifier_rf"
            else:
                best_model = gb_grid.best_estimator_
                model_name = "enhanced_url_classifier_gb"
            
            model_path = Path(__file__).parent / "saved_models" / f"{model_name}_kaggle.joblib"
            joblib.dump(best_model, model_path)
            logger.info(f"Enhanced model saved to {model_path}")
            
        except Exception as e:
            logger.error(f"Error training enhanced models: {e}")
            raise
    
    def run_training_pipeline(self):
        """Run the complete training pipeline"""
        logger.info("Starting Kaggle dataset training pipeline...")
        start_time = time.time()
        
        try:
            # Step 1: Load and preprocess data
            self.load_and_preprocess_data()
            
            # Step 2: Train basic models
            self.train_url_classifier()
            self.train_content_analyzer()
            
            # Step 3: Train enhanced models
            self.train_enhanced_models()
            
            total_time = time.time() - start_time
            logger.info(f"Training pipeline completed in {total_time:.2f} seconds")
            
            # Summary
            logger.info("=" * 50)
            logger.info("TRAINING SUMMARY")
            logger.info("=" * 50)
            logger.info(f"Dataset size: {len(self.data)} URLs")
            logger.info("Models trained:")
            logger.info("  - URL Classifier (Random Forest)")
            logger.info("  - Content Analyzer (Random Forest)")
            logger.info("  - Enhanced URL Classifier (GridSearch optimized)")
            logger.info("=" * 50)
            
        except Exception as e:
            logger.error(f"Training pipeline failed: {e}")
            raise

def main():
    """Main function to run the training"""
    try:
        # Get dataset path from command line arguments
        import sys
        dataset_path = sys.argv[1] if len(sys.argv) > 1 else "malicious_phish.csv"
        
        # Initialize trainer
        trainer = KaggleDatasetTrainer(dataset_path=dataset_path)
        
        # Run training pipeline
        trainer.run_training_pipeline()
        
        logger.info("Training completed successfully!")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
