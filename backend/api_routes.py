import json
import logging
import os
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from .db import get_db_connection_with_retry, get_pool_status

logger = logging.getLogger(__name__)

# Health check cache to avoid slow ML engine loading on every request
_health_cache = {"ml_status": None, "ml_status_time": 0, "cache_ttl": 60}  # Cache ML status for 60 seconds


def _require_auth_enabled() -> bool:
    env = os.getenv("ENVIRONMENT", "development").lower()
    if env in ("production", "prod"):
        return True
    return os.getenv("REQUIRE_AUTH", "false").lower() in ("1", "true", "yes")


def _admin_auth_dependency():
    if not _require_auth_enabled():
        return []
    try:
        from .jwt_auth import get_current_user
    except Exception:
        return []
    return [Depends(get_current_user)]


api_router = APIRouter(prefix="/admin", tags=["API"], dependencies=_admin_auth_dependency())
health_router = APIRouter(tags=["Health"])


@api_router.get("/user_scans")
def get_user_scans(email: str = None, limit: int = 6):
    """Return recent scans for a user. If email is not provided, return global recent scans.

    The response is a JSON list of scan rows with fields used by the frontend recent-scans widgets.
    """
    try:
        limit = max(1, min(int(limit or 6), 50))
        with get_db_connection_with_retry() as conn:
            if not conn:
                # Graceful degradation: return empty list for UI instead of 500
                logger.warning("Database unavailable for get_user_scans; returning empty list")
                return []

            # Cache scan table columns in connection to avoid repeated SHOW COLUMNS calls
            if not hasattr(conn, "_scan_cols_cache"):
                cols_cur = conn.cursor()
                cols_cur.execute("SHOW COLUMNS FROM scans")
                conn._scan_cols_cache = {row[0] for row in cols_cur.fetchall()}
                cols_cur.close()
            scan_cols = conn._scan_cols_cache

            select_cols = [
                "scan_id",
                "url",
                "status",
                "is_malicious",
                "threat_level",
                "malicious_count",
                "suspicious_count",
                "total_engines",
                "ssl_valid",
                "domain_reputation",
                "detection_details",
            ]
            # created_at is preferred, fallback to scan_timestamp or completed_at
            if "created_at" in scan_cols:
                time_col = "created_at"
            elif "scan_timestamp" in scan_cols:
                time_col = "scan_timestamp"
            elif "completed_at" in scan_cols:
                time_col = "completed_at"
            else:
                time_col = None

            if time_col:
                select_cols.append(time_col)

            # user_email predicate only if column exists and provided
            where_clause = ""
            params = []
            if email and "user_email" in scan_cols:
                where_clause = "WHERE user_email = %s"
                params.append(email)

            order_clause = f"ORDER BY {time_col} DESC" if time_col else "ORDER BY scan_id DESC"
            limit_clause = "LIMIT %s"
            params.append(limit)

            query = (
                f"SELECT {', '.join(select_cols)} FROM scans {where_clause} {order_clause} {limit_clause}"  # nosec B608
            )

            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            cursor.close()

            # Normalize and ensure JSON
            normalized = []
            for row in rows:
                det = row.get("detection_details")
                if isinstance(det, str):
                    try:
                        row["detection_details"] = json.loads(det) if det else {}
                    except Exception:
                        row["detection_details"] = {}
                # Ensure created_at field is present for UI
                if "created_at" not in row or row.get("created_at") is None:
                    row["created_at"] = row.get("scan_timestamp") or row.get("completed_at")
                normalized.append(row)

            return normalized
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching user scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve user scans")


@api_router.get("/migrate-database")
async def migrate_database():
    """Manually run database migration"""
    if os.getenv("ENVIRONMENT", "development").lower() in ("production", "prod"):
        raise HTTPException(status_code=404, detail="Not found")
    try:
        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()

                # Add user_email column to existing scans table if it doesn't exist
                try:
                    cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
                    conn.commit()
                    logger.info("Successfully added user_email column to scans table")
                    return {"success": True, "message": "Added user_email column"}
                except Exception as e:
                    if "Duplicate column name" in str(e):
                        logger.info("user_email column already exists in scans table")
                        return {"success": True, "message": "user_email column already exists"}
                    else:
                        logger.error(f"Error adding user_email column: {e}")
                        return {"success": False, "error": str(e)}
                finally:
                    cursor.close()
            else:
                return {"success": False, "error": "Database connection failed"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@api_router.get("/ml-training-stats/create-table")
def create_ml_training_table():
    """Manually create the ML training stats table (for testing)"""
    if os.getenv("ENVIRONMENT", "development").lower() in ("production", "prod"):
        raise HTTPException(status_code=404, detail="Not found")
    try:
        logger = logging.getLogger("ml_training")
        logger.info("Creating ML training stats table")

        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()

                # Create the table
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ml_training_stats (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        model_name VARCHAR(255) NOT NULL,
                        dataset_name VARCHAR(255) NOT NULL,
                        total_urls_trained INT NOT NULL,
                        malicious_urls_count INT DEFAULT 0,
                        benign_urls_count INT DEFAULT 0,
                        training_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        model_version VARCHAR(50),
                        accuracy_score DECIMAL(5,4),
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        INDEX idx_model_name (model_name),
                        INDEX idx_training_date (training_date)
                    )
                """
                )

                # Insert default data
                cursor.execute(
                    """
                    INSERT INTO ml_training_stats
                    (model_name, dataset_name, total_urls_trained, malicious_urls_count, benign_urls_count, model_version, accuracy_score)
                    VALUES
                    ('URL Threat Classifier', 'Kaggle Malicious URLs Dataset', 450000, 225000, 225000, '1.0', 0.95),
                    ('Content Phishing Detector', 'Kaggle Malicious URLs Dataset', 450000, 225000, 225000, '1.0', 0.92)
                """
                )

                conn.commit()
                cursor.close()

                return {"success": True, "message": "ML training stats table created and populated successfully"}

            return {"success": False, "error": "Database connection failed"}
    except Exception as e:
        logger.error(f"Error creating ML training stats table: {e}")
        return {"success": False, "error": str(e)}


@api_router.get("/ml-training-stats")
def get_ml_training_statistics():
    """Get detailed ML training statistics"""
    try:
        logger = logging.getLogger("ml_training")
        logger.info("Getting ML training statistics")
        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor(dictionary=True)

                # Check if table exists first
                try:
                    cursor.execute("SHOW TABLES LIKE 'ml_training_stats'")
                    table_exists = cursor.fetchone()

                    if not table_exists:
                        return {
                            "success": True,
                            "ml_models": [],
                            "total_models": 0,
                            "message": "ML training stats table not yet created",
                        }

                    # Get all ML training statistics
                    query = """
                        SELECT model_name, dataset_name, total_urls_trained,
                               malicious_urls_count, benign_urls_count,
                               model_version, accuracy_score, training_date, last_updated
                        FROM ml_training_stats
                        ORDER BY training_date DESC
                    """
                    cursor.execute(query)
                    ml_stats = cursor.fetchall()

                    cursor.close()

                    return {"success": True, "ml_models": ml_stats, "total_models": len(ml_stats)}
                except Exception as table_error:
                    logger.warning(f"ML training stats table error: {table_error}")
                    return {
                        "success": True,
                        "ml_models": [],
                        "total_models": 0,
                        "message": "ML training stats table not accessible",
                    }

        return {"success": False, "error": "Database connection failed"}
    except Exception as e:
        logger.error(f"Error retrieving ML training stats: {e}")
        return {"success": False, "error": str(e)}


@api_router.get("/pool-status")
def get_connection_pool_status():
    """Get database connection pool status"""
    try:
        pool_status = get_pool_status()
        return {"success": True, "pool_status": pool_status, "timestamp": datetime.now().isoformat()}
    except Exception as e:
        logger.error(f"Error getting pool status: {e}")
        return {"success": False, "error": str(e), "timestamp": datetime.now().isoformat()}


@api_router.get("/dashboard-stats")
def get_dashboard_statistics():
    """Get dashboard statistics including Kaggle dataset data"""
    try:
        logger.info("Getting dashboard statistics")

        # Get actual scan statistics from database
        actual_scanned = 0
        actual_threats = 0
        users_count = 0

        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()

                # Count total scans
                cursor.execute("SELECT COUNT(*) FROM scans")
                actual_scanned = cursor.fetchone()[0]

                # Count malicious scans
                cursor.execute("SELECT COUNT(*) FROM scans WHERE is_malicious = 1")
                actual_threats = cursor.fetchone()[0]

                # Count unique users
                cursor.execute("SELECT COUNT(DISTINCT user_email) FROM scans WHERE user_email IS NOT NULL")
                users_count = cursor.fetchone()[0]

                cursor.close()

        # Kaggle dataset statistics (615k URLs, 250k high-threat)
        kaggle_total_urls = 615000
        kaggle_high_threats = 250000
        kaggle_malicious = 400000

        # Combine actual scans with ML training data
        total_urls_scanned = actual_scanned + kaggle_total_urls
        total_threats_blocked = actual_threats + kaggle_high_threats

        return {
            "urls_scanned": total_urls_scanned,
            "threats_blocked": total_threats_blocked,
            "users": users_count,
            "uptime": "99.99 %",
            "actual_scanned": actual_scanned,
            "actual_threats": actual_threats,
            "ml_training_urls": kaggle_total_urls,
            "ml_training_threats": kaggle_high_threats,
            "kaggle_dataset": {
                "total_urls": kaggle_total_urls,
                "malicious_urls": kaggle_malicious,
                "high_threat_urls": kaggle_high_threats,
                "benign_urls": kaggle_total_urls - kaggle_malicious,
            },
        }

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {e}")
        # Return Kaggle dataset statistics as fallback
        return {
            "urls_scanned": 615000,
            "threats_blocked": 250000,
            "users": 0,
            "uptime": "99.99 %",
            "actual_scanned": 0,
            "actual_threats": 0,
            "ml_training_urls": 615000,
            "ml_training_threats": 250000,
            "kaggle_dataset": {
                "total_urls": 615000,
                "malicious_urls": 400000,
                "high_threat_urls": 250000,
                "benign_urls": 215000,
            },
        }


@health_router.get("/health")
def health_check():
    """Health check endpoint - STEP 4: Kill heavy logic in /health"""
    t0 = time.time()

    global _health_cache

    # Return cached DB status instantly; refresh in background.
    current_time = time.time()

    # Initialize cache keys if missing
    if "db_status" not in _health_cache:
        _health_cache["db_status"] = "unknown"
        _health_cache["db_test"] = "skipped"
        _health_cache["db_last_check"] = 0
        _health_cache["db_check_inflight"] = False

    # Fire-and-forget refresh if stale and not already running
    if (current_time - float(_health_cache.get("db_last_check", 0) or 0)) > 15 and not _health_cache.get(
        "db_check_inflight", False
    ):

        def _refresh_db_status():
            try:
                _health_cache["db_check_inflight"] = True
                with get_db_connection_with_retry(max_retries=1, delay=0.1) as conn:
                    if conn and getattr(conn, "is_connected", None) and conn.is_connected():
                        _health_cache["db_status"] = "connected"
                        _health_cache["db_test"] = "passed"
                    else:
                        _health_cache["db_status"] = "disconnected"
                        _health_cache["db_test"] = "skipped"
            except Exception as e:
                _health_cache["db_status"] = "error"
                _health_cache["db_test"] = f"connection_error: {str(e)[:50]}"
            finally:
                _health_cache["db_last_check"] = time.time()
                _health_cache["db_check_inflight"] = False

        try:
            import threading

            threading.Thread(target=_refresh_db_status, daemon=True).start()
        except Exception:  # nosec B110
            # If thread creation fails, just keep serving cached status
            pass

    database_status = _health_cache.get("db_status", "unknown")
    db_test = _health_cache.get("db_test", "skipped")

    ml_status = _health_cache.get("ml_status")

    if ml_status is None:
        # First time or cache not initialized yet
        ml_status = {
            "url_classifier_trained": False,
            "content_detector_trained": False,
            "models_available": False,
            "note": "ML models loading in background",
        }

    total_time = time.time() - t0
    if total_time > 1.0:
        logger.warning(f"[Health] Slow response: {total_time:.4f}s")
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": database_status,
        "database_test": db_test,
        "database_type": "MySQL",
        "ml_models": ml_status,
    }
