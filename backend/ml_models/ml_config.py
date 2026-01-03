"""
ML Configuration for WebShield
Controls parallel processing and resource usage
"""

import logging
import os

logger = logging.getLogger(__name__)


class MLConfig:
    """ML Configuration class to control resource usage"""

    # Parallel processing limits
    # CRITICAL FIX: Use n_jobs=1 to prevent asyncio event loop conflicts on Windows
    MAX_PARALLEL_JOBS = 1  # FIXED: Changed from 2 to 1 to avoid asyncio conflicts
    MAX_OMP_THREADS = 1
    MAX_MKL_THREADS = 1

    # Model complexity limits
    MAX_ESTIMATORS = 100
    MAX_TREE_DEPTH = 20
    MAX_NEURAL_LAYERS = 2
    MAX_NEURAL_NEURONS = 100

    # Training limits
    MAX_ITERATIONS = 1000
    BATCH_SIZE = 1000

    @classmethod
    def configure_environment(cls):
        """Configure environment variables for optimal performance"""
        env_vars = {
            "SKLEARN_N_JOBS": str(cls.MAX_PARALLEL_JOBS),
            "OMP_NUM_THREADS": str(cls.MAX_OMP_THREADS),
            "MKL_NUM_THREADS": str(cls.MAX_MKL_THREADS),
            "NUMEXPR_NUM_THREADS": str(cls.MAX_OMP_THREADS),
            "JOBLIB_MULTIPROCESSING": "0",  # Disable multiprocessing
            "LOKY_MAX_CPU_COUNT": "1",  # Force loky backend to use single CPU
        }

        for key, value in env_vars.items():
            os.environ[key] = value
            logger.debug(f"Set {key}={value}")

        logger.info(f"🔧 ML environment configured: max_jobs={cls.MAX_PARALLEL_JOBS}")

    @classmethod
    def get_rf_params(cls):
        """Get optimized RandomForest parameters"""
        return {
            "n_estimators": cls.MAX_ESTIMATORS,
            "max_depth": cls.MAX_TREE_DEPTH,
            "n_jobs": cls.MAX_PARALLEL_JOBS,
            "random_state": 42,
        }

    @classmethod
    def get_gb_params(cls):
        """Get optimized GradientBoosting parameters"""
        return {
            "n_estimators": cls.MAX_ESTIMATORS,
            "max_depth": cls.MAX_TREE_DEPTH // 2,
            "learning_rate": 0.1,
            "random_state": 42,
        }

    @classmethod
    def get_nn_params(cls):
        """Get optimized Neural Network parameters"""
        return {
            "hidden_layer_sizes": (cls.MAX_NEURAL_NEURONS, cls.MAX_NEURAL_NEURONS // 2),
            "max_iter": cls.MAX_ITERATIONS,
            "random_state": 42,
        }


# Configure environment on import
MLConfig.configure_environment()
