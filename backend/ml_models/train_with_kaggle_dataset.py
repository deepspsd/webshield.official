#!/usr/bin/env python3
"""
Train ML Models with Kaggle Malicious URLs Dataset
This script trains both URL classifier and content analyzer using the comprehensive dataset

=============================================================================
GOOGLE COLAB SETUP INSTRUCTIONS:
=============================================================================

1. Install dependencies:
   !pip install pandas numpy scikit-learn joblib beautifulsoup4

2. Upload these files to Colab (use the file upload button on the left):
   - train_with_kaggle_dataset.py (this file)
   - url_classifier.py
   - content_analyzer.py
   - malicious_phish.csv (download from Kaggle)

3. Run the training:
   !python train_with_kaggle_dataset.py --max-samples 50000

   Or for full dataset (may take 1-2 hours):
   !python train_with_kaggle_dataset.py malicious_phish.csv

4. Download trained models:
   - Files will be saved in ./saved_models/ directory
   - Download: url_classifier_kaggle.joblib
   - Download: content_analyzer_kaggle.joblib
   - Download: content_vectorizer_kaggle.joblib

=============================================================================
"""

import logging
import os
import sys
import time
import urllib.parse
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import GridSearchCV, cross_val_score, train_test_split

warnings.filterwarnings("ignore")

# Configure logging BEFORE imports (needed for error messages)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Use absolute imports for running directly
URLThreatClassifier = None
ContentPhishingDetector = None

try:
    # Try backend imports first (for running from project root)
    from backend.ml_models.content_analyzer import ContentPhishingDetector
    from backend.ml_models.url_classifier import URLThreatClassifier
    logger.info("✓ Successfully imported classifiers from backend.ml_models")
except ImportError as e1:
    try:
        # Fallback for direct execution (same directory) - COLAB USES THIS
        current_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
        if current_dir not in sys.path:
            sys.path.insert(0, current_dir)

        from content_analyzer import ContentPhishingDetector
        from url_classifier import URLThreatClassifier

        logger.info("✓ Successfully imported classifiers from current directory (Colab mode)")
    except ImportError as e2:
        logger.error("=" * 60)
        logger.error("❌ IMPORT ERROR: Could not import ML classifiers!")
        logger.error("=" * 60)
        logger.error("\nFiles found in current directory:")
        try:
            import os

            files = [f for f in os.listdir(".") if f.endswith(".py") or f.endswith(".csv")]
            for f in files:
                logger.error(f"  ✓ {f}")
        except Exception:  # nosec B110
            pass
        logger.error("\nFor Google Colab, you need to:")
        logger.error("1. Upload these files to Colab:")
        logger.error("   - url_classifier.py")
        logger.error("   - content_analyzer.py")
        logger.error("   - malicious_phish.csv")
        logger.error("\n2. Install dependencies:")
        logger.error("   !pip install pandas numpy scikit-learn joblib beautifulsoup4")
        logger.error("\n3. Restart runtime and try again")
        logger.error("=" * 60)
        logger.error("\nOriginal errors:")
        logger.error(f"  - Backend import: {e1}")
        logger.error(f"  - Direct import: {e2}")
        logger.error("=" * 60)
        raise ImportError(
            "Could not import URLThreatClassifier and ContentPhishingDetector. "
            "Please check that url_classifier.py and content_analyzer.py are uploaded."
        ) from e2


class KaggleDatasetTrainer:
    """Trainer class for using Kaggle malicious URLs dataset"""

    def __init__(self, dataset_path: str = "malicious_phish.csv", max_samples: int = None):
        # Handle relative paths - if the file doesn't exist in current dir,
        # try to find it relative to the script location
        if not os.path.exists(dataset_path):
            try:
                script_dir = Path(__file__).parent
                potential_path = script_dir / dataset_path
                if potential_path.exists():
                    self.dataset_path = str(potential_path)
                    logger.info(f"Found dataset at: {self.dataset_path}")
                else:
                    self.dataset_path = dataset_path
            except Exception:
                # Colab environment - use current directory
                self.dataset_path = dataset_path
        else:
            self.dataset_path = dataset_path

        self.max_samples = max_samples  # Limit samples to prevent crashes
        self.data = None

        # Initialize classifiers (imports already validated above)
        logger.info("Initializing ML classifiers...")
        try:
            self.url_classifier = URLThreatClassifier()
            logger.info("✓ URL classifier initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize URLThreatClassifier: {e}")
            raise

        try:
            self.content_analyzer = ContentPhishingDetector()
            logger.info("✓ Content analyzer initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize ContentPhishingDetector: {e}")
            raise

    def load_and_preprocess_data(self):
        """Load and preprocess the Kaggle dataset"""
        logger.info("Loading Kaggle dataset...")

        try:
            # Check if file exists
            if not os.path.exists(self.dataset_path):
                raise FileNotFoundError(
                    f"\n{'='*60}\n"
                    "ERROR: Dataset file not found!\n"
                    f"Looking for: {self.dataset_path}\n\n"
                    "For Google Colab:\n"
                    "1. Upload 'malicious_phish.csv' using the file upload button\n"
                    "2. Or mount Google Drive and provide the correct path\n"
                    "3. Or download from: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset\n"
                    f"{'='*60}"
                )

            # Load the CSV file with memory optimization
            logger.info("Reading CSV in chunks to prevent memory crash...")
            if self.max_samples:
                self.data = pd.read_csv(self.dataset_path, nrows=self.max_samples)
                logger.info(f"✓ Loaded {len(self.data):,} URLs (limited to {self.max_samples:,} for stability)")
            else:
                # Load in chunks to prevent memory issues
                chunk_size = 50000
                chunks = []
                logger.info("Loading dataset in chunks...")
                for i, chunk in enumerate(pd.read_csv(self.dataset_path, chunksize=chunk_size)):
                    chunks.append(chunk)
                    total_so_far = sum(len(c) for c in chunks)
                    logger.info(f"  Chunk {i+1}: {len(chunk):,} rows (Total: {total_so_far:,})")
                self.data = pd.concat(chunks, ignore_index=True)
                logger.info(f"✓ Loaded {len(self.data):,} URLs from dataset")

            # Display basic info
            logger.info(f"Dataset columns: {list(self.data.columns)}")
            logger.info(f"Dataset shape: {self.data.shape}")

            # Auto-detect column names (handle different CSV formats)
            url_column = None
            type_column = None

            # Common column name variations
            url_variations = ["url", "URL", "urls", "link", "Link", "website"]
            type_variations = ["type", "Type", "label", "Label", "class", "Class", "category"]

            for col in self.data.columns:
                if col in url_variations:
                    url_column = col
                if col in type_variations:
                    type_column = col

            # If not found, use first column as URL and second as type
            if url_column is None:
                url_column = self.data.columns[0]
                logger.warning(f"URL column not found, using first column: '{url_column}'")

            if type_column is None and len(self.data.columns) > 1:
                type_column = self.data.columns[1]
                logger.warning(f"Type column not found, using second column: '{type_column}'")

            logger.info(f"✓ Using URL column: '{url_column}'")
            logger.info(f"✓ Using Type column: '{type_column}'")

            # Check for missing values
            missing_values = self.data.isnull().sum()
            if missing_values.sum() > 0:
                logger.info(f"Missing values:\n{missing_values[missing_values > 0]}")

            # Display class distribution
            if type_column and type_column in self.data.columns:
                class_distribution = self.data[type_column].value_counts()
                logger.info(f"Class distribution:\n{class_distribution}")

                # Map classes to binary (malicious vs benign)
                # Handle different label formats
                self.data["is_malicious"] = self.data[type_column].apply(
                    lambda x: 0 if str(x).lower() in ["benign", "legitimate", "safe", "0", "good"] else 1
                )

                logger.info(f"Binary classification distribution:\n{self.data['is_malicious'].value_counts()}")
            else:
                logger.warning("No type column found, assuming all URLs need classification")
                self.data["is_malicious"] = 1  # Default to malicious for unlabeled data

            # Clean URLs
            self.data["url_clean"] = self.data[url_column].apply(self._clean_url)

            # Remove rows with invalid URLs
            valid_urls = self.data["url_clean"].notna()
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
            if not url.startswith(("http://", "https://")):
                url = "http://" + url

            # Parse URL to validate
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                return None

            return url
        except Exception:
            return None

    def train_url_classifier(self):
        """Train the URL classifier with enhanced features"""
        logger.info("Training URL classifier...")

        try:
            # Extract features for all URLs
            logger.info("Extracting URL features...")
            feature_data = []
            labels = []

            # Process in batches to prevent memory issues
            batch_size = 5000
            total_rows = len(self.data)

            for start_idx in range(0, total_rows, batch_size):
                end_idx = min(start_idx + batch_size, total_rows)
                logger.info(f"Processing URLs {start_idx}-{end_idx}/{total_rows} ({(end_idx/total_rows)*100:.1f}%)")

                batch = self.data.iloc[start_idx:end_idx]

                for _idx, row in batch.iterrows():
                    try:
                        features = self.url_classifier.extract_features(row["url_clean"])
                        feature_data.append(features)
                        labels.append(row["is_malicious"])
                    except Exception:  # nosec B112
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

            # Train the classifier with memory-efficient settings
            logger.info("Training Random Forest classifier (this may take 20-40 minutes)...")
            # Reduce n_estimators to prevent memory crash
            # Use single RandomForest instead of ensemble for Colab compatibility
            # CRITICAL FIX: Use n_jobs=1 to prevent asyncio event loop conflicts
            self.url_classifier.classifier = RandomForestClassifier(
                n_estimators=100,  # Optimized for Colab
                max_depth=20,  # Limit tree depth
                min_samples_split=5,
                n_jobs=1,  # FIXED: Single thread to avoid asyncio conflicts
                random_state=42,
                verbose=1,  # Show progress
            )

            logger.info("Fitting model... (progress will be shown below)")
            self.url_classifier.classifier.fit(X_train, y_train)
            logger.info("✓ Random Forest training completed!")

            # Evaluate
            y_pred = self.url_classifier.classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            logger.info(f"URL Classifier Accuracy: {accuracy:.4f}")
            logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")

            # Cross-validation (reduced folds to save time and memory)
            logger.info("Running cross-validation (this may take 10-15 minutes)...")
            try:
                # CRITICAL FIX: Use n_jobs=1 to prevent asyncio event loop conflicts
                cv_scores = cross_val_score(self.url_classifier.classifier, X_train, y_train, cv=3, n_jobs=1)
                logger.info(f"Cross-validation scores: {cv_scores}")
                logger.info(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            except Exception as cv_error:
                logger.warning(f"Cross-validation failed (skipping): {cv_error}")
                logger.info("Continuing without cross-validation...")

            # Save the trained model
            try:
                # Try to use script directory first
                model_dir = Path(__file__).parent / "saved_models"
            except Exception:
                # Fallback for Colab - use current directory
                model_dir = Path("./saved_models")

            model_dir.mkdir(exist_ok=True)
            model_path = model_dir / "url_classifier_kaggle.joblib"

            joblib.dump(self.url_classifier.classifier, model_path)
            logger.info(f"✓ URL classifier saved to {model_path}")

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

            # Process in batches to prevent memory issues
            batch_size = 5000
            total_rows = len(self.data)

            for start_idx in range(0, total_rows, batch_size):
                end_idx = min(start_idx + batch_size, total_rows)
                logger.info(f"Processing content {start_idx}-{end_idx}/{total_rows} ({(end_idx/total_rows)*100:.1f}%)")

                batch = self.data.iloc[start_idx:end_idx]

                for _idx, row in batch.iterrows():
                    try:
                        # Create synthetic content based on URL
                        url_text = row["url_clean"].lower()

                        # Extract domain and path for text analysis
                        parsed = urllib.parse.urlparse(url_text)
                        domain_text = parsed.netloc.replace(".", " ")
                        path_text = parsed.path.replace("/", " ").replace("-", " ").replace("_", " ")

                        # Combine text features
                        combined_text = f"{domain_text} {path_text} {parsed.query}"

                        url_texts.append(combined_text)
                        labels.append(row["is_malicious"])

                    except Exception:  # nosec B112
                        continue

            # Vectorize text features with memory-efficient settings
            logger.info("Vectorizing text features (this may take 5-10 minutes)...")
            vectorizer = TfidfVectorizer(
                max_features=1000,  # Reduced from 2000 to save memory
                ngram_range=(1, 2),  # Reduced from (1,3) to save memory
                min_df=10,  # Increased to reduce features
                max_df=0.7,  # More aggressive filtering
            )

            X_text = vectorizer.fit_transform(url_texts)
            labels = np.array(labels)

            logger.info(f"Text feature matrix shape: {X_text.shape}")

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X_text, labels, test_size=0.2, random_state=42, stratify=labels
            )

            # Train content analyzer with simplified model for Colab
            logger.info("Training content analyzer (using simplified RandomForest)...")

            # Replace ensemble with single RandomForest for Colab compatibility
            # CRITICAL FIX: Use n_jobs=1 to prevent asyncio event loop conflicts
            self.content_analyzer.classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                n_jobs=1,  # FIXED: Single thread to avoid asyncio conflicts
                random_state=42,
                verbose=1,
            )

            logger.info("Fitting content analyzer... (progress will be shown below)")
            self.content_analyzer.classifier.fit(X_train, y_train)

            # Evaluate
            y_pred = self.content_analyzer.classifier.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)

            logger.info(f"Content Analyzer Accuracy: {accuracy:.4f}")
            logger.info(f"Classification Report:\n{classification_report(y_test, y_pred)}")

            # Save the trained model and vectorizer
            try:
                model_dir = Path(__file__).parent / "saved_models"
            except Exception:
                # Fallback for Colab
                model_dir = Path("./saved_models")

            model_dir.mkdir(exist_ok=True)

            content_model_path = model_dir / "content_analyzer_kaggle.joblib"
            vectorizer_path = model_dir / "content_vectorizer_kaggle.joblib"

            joblib.dump(self.content_analyzer.classifier, content_model_path)
            joblib.dump(vectorizer, vectorizer_path)

            logger.info(f"✓ Content analyzer saved to {content_model_path}")
            logger.info(f"✓ Vectorizer saved to {vectorizer_path}")

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
                    features = self.url_classifier.extract_features(row["url_clean"])
                    feature_data.append(features)
                    labels.append(row["is_malicious"])
                except Exception:  # nosec B112
                    continue

            feature_df = pd.DataFrame(feature_data)
            labels = np.array(labels)

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                feature_df, labels, test_size=0.2, random_state=42, stratify=labels
            )

            # Grid search for Random Forest
            rf_param_grid = {
                "n_estimators": [100, 200, 300],
                "max_depth": [10, 20, None],
                "min_samples_split": [2, 5, 10],
                "min_samples_leaf": [1, 2, 4],
            }

            logger.info("Performing GridSearch for Random Forest...")
            # CRITICAL FIX: Use n_jobs=1 to prevent asyncio event loop conflicts
            rf_grid = GridSearchCV(
                RandomForestClassifier(random_state=42),
                rf_param_grid,
                cv=3,
                n_jobs=1,  # FIXED: Single thread to avoid asyncio conflicts
                verbose=1,
            )

            rf_grid.fit(X_train, y_train)

            logger.info(f"Best Random Forest parameters: {rf_grid.best_params_}")
            logger.info(f"Best Random Forest score: {rf_grid.best_score_:.4f}")

            # Grid search for Gradient Boosting
            gb_param_grid = {"n_estimators": [100, 200], "learning_rate": [0.1, 0.2], "max_depth": [3, 5, 7]}

            logger.info("Performing GridSearch for Gradient Boosting...")
            # CRITICAL FIX: Use n_jobs=1 to prevent asyncio event loop conflicts
            gb_grid = GridSearchCV(
                GradientBoostingClassifier(random_state=42),
                gb_param_grid,
                cv=3,
                n_jobs=1,  # FIXED: Single thread to avoid asyncio conflicts
                verbose=1,
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

            try:
                model_dir = Path(__file__).parent / "saved_models"
            except Exception:
                model_dir = Path("./saved_models")

            model_dir.mkdir(exist_ok=True)
            model_path = model_dir / f"{model_name}_kaggle.joblib"

            joblib.dump(best_model, model_path)
            logger.info(f"✓ Enhanced model saved to {model_path}")

        except Exception as e:
            logger.error(f"Error training enhanced models: {e}")
            raise

    def run_training_pipeline(self, skip_enhanced=False):
        """Run the complete training pipeline"""
        logger.info("Starting Kaggle dataset training pipeline...")
        logger.info("=" * 60)
        logger.info("MEMORY-OPTIMIZED TRAINING MODE ENABLED")
        logger.info("This prevents terminal crashes with large datasets")
        logger.info("=" * 60)
        start_time = time.time()

        try:
            # Step 1: Load and preprocess data
            logger.info("\n[STEP 1/3] Loading and preprocessing data...")
            self.load_and_preprocess_data()

            # Step 2: Train basic models
            logger.info("\n[STEP 2/3] Training URL classifier...")
            self.train_url_classifier()

            logger.info("\n[STEP 3/3] Training content analyzer...")
            self.train_content_analyzer()

            # Step 3: Train enhanced models (optional - skip to prevent crashes)
            if not skip_enhanced:
                logger.info("\n[OPTIONAL] Training enhanced models with hyperparameter tuning...")
                logger.info("WARNING: This may take 1-2 hours and use significant memory")
                self.train_enhanced_models()
            else:
                logger.info("\n[SKIPPED] Enhanced model training (use --enhanced flag to enable)")

            total_time = time.time() - start_time
            hours = int(total_time // 3600)
            minutes = int((total_time % 3600) // 60)
            seconds = int(total_time % 60)

            if hours > 0:
                time_str = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                time_str = f"{minutes}m {seconds}s"
            else:
                time_str = f"{seconds}s"

            logger.info(f"\n✓ Training pipeline completed in {time_str} ({total_time:.2f} seconds)")

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
    import argparse

    parser = argparse.ArgumentParser(description="Train WebShield ML models with Kaggle dataset")
    parser.add_argument(
        "dataset_path", nargs="?", default="malicious_phish.csv", help="Path to the malicious_phish.csv dataset"
    )
    parser.add_argument(
        "--max-samples", type=int, default=None, help="Limit number of samples (e.g., 100000 for testing)"
    )
    parser.add_argument(
        "--enhanced", action="store_true", help="Enable enhanced model training with hyperparameter tuning (slower)"
    )

    args = parser.parse_args()

    try:
        logger.info("=" * 60)
        logger.info("WebShield ML Model Training")
        logger.info("=" * 60)
        logger.info(f"Dataset: {args.dataset_path}")
        if args.max_samples:
            logger.info(f"Sample limit: {args.max_samples:,} URLs")
            logger.info("(Using limited samples for faster training)")
        else:
            logger.info("Sample limit: None (using full dataset)")
        logger.info(f"Enhanced training: {'Enabled' if args.enhanced else 'Disabled'}")
        logger.info("=" * 60)

        # Initialize trainer with memory optimization
        trainer = KaggleDatasetTrainer(dataset_path=args.dataset_path, max_samples=args.max_samples)

        # Run training pipeline
        trainer.run_training_pipeline(skip_enhanced=not args.enhanced)

        logger.info("\n" + "=" * 60)
        logger.info("✅ TRAINING COMPLETED SUCCESSFULLY!")
        logger.info("=" * 60)
        logger.info("Models saved to: backend/ml_models/saved_models/")
        logger.info("You can now run the WebShield server to use these models")
        logger.info("=" * 60)

    except KeyboardInterrupt:
        logger.warning("\n\nTraining interrupted by user")
        sys.exit(1)
    except FileNotFoundError as e:
        logger.error(f"\n❌ {e}")
        sys.exit(1)
    except ImportError as e:
        logger.error(f"\n❌ Import Error: {e}")
        logger.error("\nFor Google Colab, make sure to:")
        logger.error("1. Upload url_classifier.py and content_analyzer.py")
        logger.error("2. Or install required dependencies")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n❌ Training failed: {e}")
        import traceback

        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
