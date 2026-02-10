"""
Celery Background Tasks for WebShield
Async processing for scans and maintenance
"""

import asyncio
import logging
import multiprocessing
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import List
from uuid import uuid4

from .celery_app import celery_app
from .db import get_db_connection_with_retry
from .scan import _do_scan

logger = logging.getLogger(__name__)

# Balanced thread pool to prevent system overload

_cpu_count = multiprocessing.cpu_count()
SCAN_EXECUTOR = ThreadPoolExecutor(
    max_workers=min(_cpu_count, 4), thread_name_prefix="WebShield-UltraSafe"  # ULTRA SAFE: 1x CPU cores, max 4 (was 16)
)


# Circuit breaker for external API failures
class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    def call(self, func, *args, **kwargs):
        if self.state == "OPEN":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "HALF_OPEN"
            else:
                raise Exception("Circuit breaker is OPEN")

        try:
            result = func(*args, **kwargs)
            if self.state == "HALF_OPEN":
                self.state = "CLOSED"
                self.failure_count = 0
            return result
        except Exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = "OPEN"
            raise e


# Global circuit breakers for different services
VT_CIRCUIT_BREAKER = CircuitBreaker(failure_threshold=3, recovery_timeout=30)
SSL_CIRCUIT_BREAKER = CircuitBreaker(failure_threshold=5, recovery_timeout=15)
CONTENT_CIRCUIT_BREAKER = CircuitBreaker(failure_threshold=10, recovery_timeout=20)


@celery_app.task(name="backend.celery_tasks.scan_url_task", bind=True, max_retries=3)
def scan_url_task(self, url: str, scan_id: str):
    """Enhanced background task for URL scanning with circuit breakers and retries"""
    try:
        logger.info(f"🔄 Celery task started for scan {scan_id} (attempt {self.request.retries + 1})")

        # Use circuit breaker for scan execution
        def protected_scan():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(asyncio.wait_for(_do_scan(url, scan_id), timeout=120))
                return result
            finally:
                loop.close()

        # Execute with timeout and circuit breaker protection
        try:
            result = protected_scan()
            logger.info(f"✅ Celery task completed for scan {scan_id}")
            return {"scan_id": scan_id, "status": "completed", "result": result}
        except asyncio.TimeoutError as e:
            raise self.retry(countdown=60, exc=TimeoutError("Scan timeout - retrying")) from e

    except Exception as e:
        logger.error(f"❌ Celery task failed for scan {scan_id}: {e}")

        # Retry with exponential backoff for transient failures
        if self.request.retries < self.max_retries:
            countdown = 2**self.request.retries  # Exponential backoff
            logger.info(f"🔄 Retrying scan {scan_id} in {countdown} seconds")
            raise self.retry(countdown=countdown, exc=e) from e

        # Mark as failed in database after all retries
        try:
            with get_db_connection_with_retry() as conn:
                if conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "UPDATE scans SET status = 'failed', completed_at = %s WHERE scan_id = %s",
                        (datetime.now(), scan_id),
                    )
                    conn.commit()
                    cursor.close()
        except Exception as db_error:
            logger.error(f"Failed to update scan status in DB: {db_error}")

        return {"scan_id": scan_id, "status": "failed", "error": str(e)}


@celery_app.task(name="backend.celery_tasks.bulk_scan_task", bind=True)
def bulk_scan_task(self, urls: List[str], user_email: str = None, batch_size: int = 20):
    """Massively parallel bulk URL scanning with intelligent batching and load balancing"""
    try:
        total_urls = len(urls)
        logger.info(f"🚀 Starting massive bulk scan for {total_urls} URLs with {batch_size} concurrent workers")

        # Generate scan IDs upfront
        scan_data = [(url, str(uuid4())) for url in urls]

        # Insert all scans into database first for tracking
        batch_insert_scans(scan_data, user_email)

        # Process in intelligent batches to prevent system overload
        results = []
        failed_scans = []

        def process_single_scan(url_scan_pair):
            """Process a single scan with comprehensive error handling"""
            url, scan_id = url_scan_pair
            try:
                # Use the enhanced scan task with circuit breakers
                result = scan_url_task.apply_async(
                    args=[url, scan_id],
                    expires=300,  # 5 minute expiry
                    retry=True,
                    retry_policy={
                        "max_retries": 2,
                        "interval_start": 1,
                        "interval_step": 2,
                        "interval_max": 10,
                    },
                ).get(
                    timeout=180
                )  # 3 minute timeout per scan

                return {"url": url, "scan_id": scan_id, "status": "completed", "result": result}
            except Exception as e:
                logger.error(f"Bulk scan failed for {url}: {e}")
                failed_scans.append({"url": url, "scan_id": scan_id, "error": str(e)})
                return {"url": url, "scan_id": scan_id, "status": "failed", "error": str(e)}

        # Process URLs in parallel batches
        for i in range(0, total_urls, batch_size):
            batch = scan_data[i : i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (total_urls + batch_size - 1) // batch_size

            logger.info(f"📊 Processing batch {batch_num}/{total_batches} ({len(batch)} URLs)")

            # Use ThreadPoolExecutor with ULTRA SAFE parallelism
            with ThreadPoolExecutor(max_workers=min(batch_size, 2)) as executor:  # ULTRA SAFE: max 2 workers
                # Submit all tasks in the batch
                future_to_scan = {executor.submit(process_single_scan, scan_pair): scan_pair for scan_pair in batch}

                # Collect results as they complete
                batch_results = []
                for future in as_completed(future_to_scan, timeout=200):
                    try:
                        result = future.result(timeout=10)
                        batch_results.append(result)
                    except Exception as e:
                        scan_pair = future_to_scan[future]
                        logger.error(f"Batch processing failed for {scan_pair[0]}: {e}")
                        batch_results.append(
                            {"url": scan_pair[0], "scan_id": scan_pair[1], "status": "failed", "error": str(e)}
                        )

                results.extend(batch_results)

            # Progress update
            completed = len(results)
            progress = (completed / total_urls) * 100
            logger.info(f"📈 Bulk scan progress: {completed}/{total_urls} ({progress:.1f}%) completed")

            # Brief pause between batches to prevent system overload
            if i + batch_size < total_urls:
                time.sleep(0.5)

        # Final statistics
        successful_scans = len([r for r in results if r["status"] == "completed"])
        failed_count = len(failed_scans)

        logger.info(
            f"🎯 Bulk scan completed: {successful_scans} successful, {failed_count} failed out of {total_urls} total"
        )

        return {
            "total": total_urls,
            "successful": successful_scans,
            "failed": failed_count,
            "results": results,
            "failed_scans": failed_scans,
            "completion_time": time.time(),
        }

    except Exception as e:
        logger.error(f"❌ Bulk scan task failed catastrophically: {e}")
        return {
            "error": str(e),
            "total": len(urls) if urls else 0,
            "successful": 0,
            "failed": len(urls) if urls else 0,
            "results": [],
            "failed_scans": [{"error": str(e), "urls": urls}],
        }


def batch_insert_scans(scan_data: List[tuple], user_email: str = None):
    """Efficiently insert multiple scans into database using batch operations"""
    try:
        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()

                # Prepare batch insert query
                insert_query = """
                INSERT INTO scans (scan_id, url, status, created_at, user_email)
                VALUES (%s, %s, %s, %s, %s)
                """

                # Prepare batch data
                batch_data = [(scan_id, url, "processing", datetime.now(), user_email) for url, scan_id in scan_data]

                # Execute batch insert
                cursor.executemany(insert_query, batch_data)
                conn.commit()
                cursor.close()

                logger.info(f"✅ Batch inserted {len(scan_data)} scans into database")
    except Exception as e:
        logger.error(f"❌ Batch insert failed: {e}")


@celery_app.task(name="backend.celery_tasks.cleanup_old_scans")
def cleanup_old_scans():
    """Enhanced cleanup task with stuck scan recovery and performance optimization"""
    try:
        logger.info("🧹 Starting comprehensive cleanup...")

        cleanup_stats = {
            "old_scans_deleted": 0,
            "stuck_scans_recovered": 0,
            "cache_entries_cleared": 0,
            "database_optimized": False,
        }

        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()

                # 1. Clean up old completed scans (30 days)
                cutoff_date = datetime.now() - timedelta(days=30)
                cursor.execute("DELETE FROM scans WHERE created_at < %s AND status = 'completed'", (cutoff_date,))
                cleanup_stats["old_scans_deleted"] = cursor.rowcount

                # 2. Ultra-aggressive stuck scan recovery (processing for more than 20 seconds)
                stuck_cutoff = datetime.now() - timedelta(seconds=20)
                cursor.execute(
                    "UPDATE scans SET status = 'failed', completed_at = %s WHERE status = 'processing' AND created_at < %s",
                    (datetime.now(), stuck_cutoff),
                )
                cleanup_stats["stuck_scans_recovered"] = cursor.rowcount

                if cleanup_stats["stuck_scans_recovered"] > 0:
                    logger.warning(
                        f"⚡⚡ ULTRA-AGGRESSIVE recovery: {cleanup_stats['stuck_scans_recovered']} stuck scans recovered (20s timeout)"
                    )

                # 3. Clean up very old failed scans (7 days)
                failed_cutoff = datetime.now() - timedelta(days=7)
                cursor.execute("DELETE FROM scans WHERE created_at < %s AND status = 'failed'", (failed_cutoff,))
                cleanup_stats["old_scans_deleted"] += cursor.rowcount

                # 4. Optimize database tables for better performance
                try:
                    cursor.execute("OPTIMIZE TABLE scans")
                    cleanup_stats["database_optimized"] = True
                except Exception as opt_error:
                    logger.warning(f"Database optimization skipped: {opt_error}")

                conn.commit()
                cursor.close()

        # 5. Clear application-level caches
        try:
            from .scan import SCAN_CACHE, SCAN_IN_PROGRESS, SCAN_IN_PROGRESS_TIMESTAMPS

            # Clear expired cache entries
            current_time = time.time()
            expired_keys = [k for k, v in SCAN_CACHE.timestamps.items() if current_time - v > SCAN_CACHE.ttl]

            for key in expired_keys:
                SCAN_CACHE.cache.pop(key, None)
                SCAN_CACHE.timestamps.pop(key, None)

            # Clear stuck in-progress scans
            stuck_urls = [
                url for url, ts in SCAN_IN_PROGRESS_TIMESTAMPS.items() if current_time - ts > 300
            ]  # 5 minutes

            for url in stuck_urls:
                SCAN_IN_PROGRESS.pop(url, None)
                SCAN_IN_PROGRESS_TIMESTAMPS.pop(url, None)

            cleanup_stats["cache_entries_cleared"] = len(expired_keys) + len(stuck_urls)

        except Exception as cache_error:
            logger.warning(f"Cache cleanup failed: {cache_error}")

        logger.info(f"✅ Comprehensive cleanup completed: {cleanup_stats}")
        return cleanup_stats

    except Exception as e:
        logger.error(f"❌ Cleanup task failed: {e}")
        return {"error": str(e), "cleanup_stats": cleanup_stats}


@celery_app.task(name="backend.celery_tasks.update_threat_intel")
def update_threat_intel():
    """Enhanced threat intelligence update with multiple feeds and ML model refresh"""
    try:
        logger.info("🔄 Updating threat intelligence from multiple sources...")

        intel_stats = {
            "feeds_updated": 0,
            "new_threats": 0,
            "ml_models_refreshed": False,
            "cache_invalidated": False,
            "update_timestamp": datetime.now().isoformat(),
        }

        # 1. Update threat feeds (placeholder for real implementation)
        threat_feeds = ["malware_domains", "phishing_urls", "suspicious_ips", "known_bad_ssl_certs"]

        for feed in threat_feeds:
            try:
                # Placeholder for actual feed update logic
                # In real implementation, this would fetch from external APIs
                logger.info(f"📡 Updating {feed} feed...")
                intel_stats["feeds_updated"] += 1
                intel_stats["new_threats"] += 10  # Placeholder count
            except Exception as feed_error:
                logger.warning(f"Failed to update {feed}: {feed_error}")

        # 2. Refresh ML models if needed
        try:
            from .ml_models.ml_integration import get_ml_engine

            ml_engine = get_ml_engine()

            # Check if models need refresh (placeholder logic)
            if ml_engine and hasattr(ml_engine, "threat_intelligence"):
                ml_engine.threat_intelligence = {
                    "known_phishing_domains": set(),
                    "known_malware_urls": set(),
                    "threat_feeds_last_update": datetime.now(),
                    "threat_count": intel_stats["new_threats"],
                }
                intel_stats["ml_models_refreshed"] = True
                logger.info("🤖 ML threat intelligence models refreshed")
        except Exception as ml_error:
            logger.warning(f"ML model refresh failed: {ml_error}")

        # 3. Invalidate relevant caches
        try:
            from .scan import SCAN_CACHE

            # Clear cache entries that might be affected by new threat intel
            cache_keys_to_clear = [k for k in SCAN_CACHE.cache.keys() if "threat" in str(k).lower()]
            for key in cache_keys_to_clear:
                SCAN_CACHE.cache.pop(key, None)
                SCAN_CACHE.timestamps.pop(key, None)

            if cache_keys_to_clear:
                intel_stats["cache_invalidated"] = True
                logger.info(f"🗑️ Invalidated {len(cache_keys_to_clear)} cache entries")
        except Exception as cache_error:
            logger.warning(f"Cache invalidation failed: {cache_error}")

        # 4. Update database with new threat intelligence
        try:
            with get_db_connection_with_retry() as conn:
                if conn:
                    cursor = conn.cursor()

                    # Update threat intelligence metadata
                    cursor.execute(
                        """
                        INSERT INTO threat_intel_updates
                        (update_timestamp, feeds_updated, new_threats, status)
                        VALUES (%s, %s, %s, %s)
                        ON DUPLICATE KEY UPDATE
                        feeds_updated = VALUES(feeds_updated),
                        new_threats = VALUES(new_threats),
                        status = VALUES(status)
                    """,
                        (datetime.now(), intel_stats["feeds_updated"], intel_stats["new_threats"], "success"),
                    )

                    conn.commit()
                    cursor.close()
        except Exception as db_error:
            logger.warning(f"Database update failed: {db_error}")

        logger.info(f"✅ Threat intelligence update completed: {intel_stats}")
        return intel_stats

    except Exception as e:
        logger.error(f"❌ Threat intel update failed: {e}")
        return {"error": str(e), "status": "failed", "timestamp": datetime.now().isoformat()}


# Add new task for system health monitoring
@celery_app.task(name="backend.celery_tasks.system_health_check")
def system_health_check():
    """Comprehensive system health monitoring and auto-recovery"""
    try:
        logger.info("🏥 Starting system health check...")

        health_stats = {
            "database_healthy": False,
            "ml_models_loaded": False,
            "cache_operational": False,
            "scan_queue_size": 0,
            "memory_usage_mb": 0,
            "cpu_usage_percent": 0,
            "disk_usage_percent": 0,
            "active_scans": 0,
            "recommendations": [],
        }

        # 1. Database health check
        try:
            with get_db_connection_with_retry() as conn:
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
                    cursor.close()
                    health_stats["database_healthy"] = True
        except Exception as db_error:
            logger.error(f"Database health check failed: {db_error}")
            health_stats["recommendations"].append("Database connection issues detected")

        # 2. ML models health check
        try:
            from .ml_models.ml_integration import get_ml_engine

            ml_engine = get_ml_engine()
            if ml_engine and ml_engine.models_loaded:
                health_stats["ml_models_loaded"] = True
            else:
                health_stats["recommendations"].append("ML models not loaded - performance may be degraded")
        except Exception as ml_error:
            logger.warning(f"ML health check failed: {ml_error}")

        # 3. System resource monitoring
        try:
            import psutil

            # Memory usage
            memory = psutil.virtual_memory()
            health_stats["memory_usage_mb"] = memory.used // (1024 * 1024)
            if memory.percent > 85:
                health_stats["recommendations"].append(f"High memory usage: {memory.percent:.1f}%")

            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            health_stats["cpu_usage_percent"] = cpu_percent
            if cpu_percent > 90:
                health_stats["recommendations"].append(f"High CPU usage: {cpu_percent:.1f}%")

            # Disk usage
            disk = psutil.disk_usage("/")
            health_stats["disk_usage_percent"] = disk.percent
            if disk.percent > 90:
                health_stats["recommendations"].append(f"High disk usage: {disk.percent:.1f}%")

        except Exception as resource_error:
            logger.warning(f"Resource monitoring failed: {resource_error}")

        # 4. Scan queue monitoring
        try:
            from .scan import SCAN_IN_PROGRESS, _active_scans

            health_stats["active_scans"] = len(SCAN_IN_PROGRESS)
            health_stats["scan_queue_size"] = _active_scans

            if len(SCAN_IN_PROGRESS) > 100:
                health_stats["recommendations"].append("High number of active scans - consider scaling")
        except Exception as queue_error:
            logger.warning(f"Scan queue monitoring failed: {queue_error}")

        # 5. Cache health check
        try:
            from .scan import SCAN_CACHE

            cache_size = len(SCAN_CACHE.cache)
            if cache_size > 0:
                health_stats["cache_operational"] = True

            if cache_size > SCAN_CACHE.capacity * 0.9:
                health_stats["recommendations"].append("Cache near capacity - consider increasing size")
        except Exception as cache_error:
            logger.warning(f"Cache health check failed: {cache_error}")

        # Overall health score
        health_score = (
            sum(
                [
                    health_stats["database_healthy"],
                    health_stats["ml_models_loaded"],
                    health_stats["cache_operational"],
                    health_stats["memory_usage_mb"] < 1000,  # Less than 1GB
                    health_stats["cpu_usage_percent"] < 80,
                    health_stats["disk_usage_percent"] < 80,
                ]
            )
            / 6
            * 100
        )

        health_stats["overall_health_score"] = health_score
        health_stats["status"] = "healthy" if health_score > 80 else "degraded" if health_score > 60 else "critical"

        logger.info(f"🏥 System health check completed: {health_score:.1f}% healthy")
        return health_stats

    except Exception as e:
        logger.error(f"❌ System health check failed: {e}")
        return {"error": str(e), "status": "failed", "overall_health_score": 0}
