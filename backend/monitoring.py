"""
Advanced Monitoring and Metrics for WebShield
Prometheus metrics, health checks, and performance monitoring
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Dict

import psutil
from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

logger = logging.getLogger(__name__)

# Prometheus Metrics
REQUEST_COUNT = Counter("webshield_requests_total", "Total requests", ["method", "endpoint", "status"])
REQUEST_DURATION = Histogram("webshield_request_duration_seconds", "Request duration", ["method", "endpoint"])
SCAN_COUNT = Counter("webshield_scans_total", "Total scans performed", ["status", "threat_level"])
SCAN_DURATION = Histogram("webshield_scan_duration_seconds", "Scan processing time")
THREAT_DETECTIONS = Counter("webshield_threats_detected_total", "Threats detected", ["engine", "type"])
ML_PREDICTIONS = Counter("webshield_ml_predictions_total", "ML predictions", ["model", "prediction"])
ACTIVE_CONNECTIONS = Gauge("webshield_active_connections", "Active database connections")
SYSTEM_CPU = Gauge("webshield_system_cpu_percent", "System CPU usage")
SYSTEM_MEMORY = Gauge("webshield_system_memory_percent", "System memory usage")
CACHE_HITS = Counter("webshield_cache_hits_total", "Cache hits")
CACHE_MISSES = Counter("webshield_cache_misses_total", "Cache misses")

monitoring_router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


class PerformanceMonitor:
    """Advanced performance monitoring"""

    def __init__(self):
        self.start_time = time.time()
        self.request_times = []
        self.scan_times = []

    def record_request(self, method: str, endpoint: str, status: int, duration: float):
        """Record request metrics"""
        REQUEST_COUNT.labels(method=method, endpoint=endpoint, status=status).inc()
        REQUEST_DURATION.labels(method=method, endpoint=endpoint).observe(duration)
        self.request_times.append(duration)

        # Keep only last 1000 requests for memory efficiency
        if len(self.request_times) > 1000:
            self.request_times = self.request_times[-1000:]

    def record_scan(self, status: str, threat_level: str, duration: float):
        """Record scan metrics"""
        SCAN_COUNT.labels(status=status, threat_level=threat_level).inc()
        SCAN_DURATION.observe(duration)
        self.scan_times.append(duration)

        if len(self.scan_times) > 1000:
            self.scan_times = self.scan_times[-1000:]

    def record_threat_detection(self, engine: str, threat_type: str):
        """Record threat detection"""
        THREAT_DETECTIONS.labels(engine=engine, type=threat_type).inc()

    def record_ml_prediction(self, model: str, prediction: str):
        """Record ML prediction"""
        ML_PREDICTIONS.labels(model=model, prediction=prediction).inc()

    def record_cache_hit(self):
        """Record cache hit"""
        CACHE_HITS.inc()

    def record_cache_miss(self):
        """Record cache miss"""
        CACHE_MISSES.inc()

    def update_system_metrics(self):
        """Update system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            SYSTEM_CPU.set(cpu_percent)

            # Memory usage
            memory = psutil.virtual_memory()
            SYSTEM_MEMORY.set(memory.percent)

            # Update active connections (placeholder - would need actual DB pool)
            # ACTIVE_CONNECTIONS.set(get_active_connections())

        except Exception as e:
            logger.error(f"Error updating system metrics: {e}")

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        uptime = time.time() - self.start_time

        avg_request_time = sum(self.request_times) / len(self.request_times) if self.request_times else 0
        avg_scan_time = sum(self.scan_times) / len(self.scan_times) if self.scan_times else 0

        return {
            "uptime_seconds": uptime,
            "uptime_formatted": str(datetime.fromtimestamp(uptime) - datetime.fromtimestamp(0)),
            "total_requests": len(self.request_times),
            "total_scans": len(self.scan_times),
            "avg_request_time": round(avg_request_time, 3),
            "avg_scan_time": round(avg_scan_time, 3),
            "system_cpu_percent": psutil.cpu_percent(),
            "system_memory_percent": psutil.virtual_memory().percent,
            "disk_usage_percent": psutil.disk_usage("/").percent,
            "timestamp": datetime.now().isoformat(),
        }


# Global monitor instance
monitor = PerformanceMonitor()


@monitoring_router.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint"""
    # Update system metrics before returning
    monitor.update_system_metrics()

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


@monitoring_router.get("/health/detailed")
async def detailed_health_check():
    """Detailed health check with system information"""
    try:
        # System health
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        # Application health
        performance = monitor.get_performance_summary()

        # Database health (placeholder)
        db_status = "healthy"  # Would check actual DB connection

        # ML models health
        ml_status = "healthy"  # Would check ML models

        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_percent": disk.percent,
                "disk_free_gb": round(disk.free / (1024**3), 2),
            },
            "application": performance,
            "services": {"database": db_status, "ml_models": ml_status, "cache": "healthy"},
        }

        # Determine overall health
        if cpu_percent > 90 or memory.percent > 90 or disk.percent > 95:
            health_status["status"] = "degraded"

        return health_status

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "error": str(e), "timestamp": datetime.now().isoformat()}


@monitoring_router.get("/performance")
async def get_performance_stats():
    """Get performance statistics"""
    return monitor.get_performance_summary()


@monitoring_router.get("/alerts")
async def get_alerts():
    """Get system alerts and warnings"""
    alerts = []

    try:
        # CPU alert
        cpu_percent = psutil.cpu_percent()
        if cpu_percent > 80:
            alerts.append(
                {
                    "type": "warning" if cpu_percent < 90 else "critical",
                    "message": f"High CPU usage: {cpu_percent}%",
                    "timestamp": datetime.now().isoformat(),
                }
            )

        # Memory alert
        memory = psutil.virtual_memory()
        if memory.percent > 80:
            alerts.append(
                {
                    "type": "warning" if memory.percent < 90 else "critical",
                    "message": f"High memory usage: {memory.percent}%",
                    "timestamp": datetime.now().isoformat(),
                }
            )

        # Disk alert
        disk = psutil.disk_usage("/")
        if disk.percent > 85:
            alerts.append(
                {
                    "type": "warning" if disk.percent < 95 else "critical",
                    "message": f"High disk usage: {disk.percent}%",
                    "timestamp": datetime.now().isoformat(),
                }
            )

        return {"alerts": alerts, "count": len(alerts), "timestamp": datetime.now().isoformat()}

    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return {
            "alerts": [
                {
                    "type": "error",
                    "message": f"Failed to get system alerts: {str(e)}",
                    "timestamp": datetime.now().isoformat(),
                }
            ],
            "count": 1,
            "timestamp": datetime.now().isoformat(),
        }


# Middleware for automatic request monitoring
async def monitoring_middleware(request, call_next):
    """Middleware to automatically monitor requests"""
    start_time = time.time()

    try:
        response = await call_next(request)
        duration = time.time() - start_time

        # Record metrics
        monitor.record_request(
            method=request.method, endpoint=str(request.url.path), status=response.status_code, duration=duration
        )

        return response

    except Exception as e:
        duration = time.time() - start_time
        monitor.record_request(method=request.method, endpoint=str(request.url.path), status=500, duration=duration)
        raise


# Background task for continuous monitoring
async def background_monitoring():
    """Background task for continuous system monitoring"""
    while True:
        try:
            monitor.update_system_metrics()
            await asyncio.sleep(30)  # Update every 30 seconds
        except Exception as e:
            logger.error(f"Background monitoring error: {e}")
            await asyncio.sleep(60)  # Wait longer on error
