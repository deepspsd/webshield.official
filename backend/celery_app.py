"""
Celery Configuration for Background Task Processing
Handles async scan processing and scheduled tasks
"""

from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize Celery
celery_app = Celery(
    'webshield',
    broker=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('REDIS_URL', 'redis://localhost:6379/0')
)

# High-performance Celery configuration for massive scale
celery_app.conf.update(
    # Serialization
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task execution settings
    task_track_started=True,
    task_time_limit=180,  # 3 minutes max per task (reduced for faster recovery)
    task_soft_time_limit=150,  # 2.5 minutes soft limit
    task_acks_late=True,  # Acknowledge tasks only after completion
    task_reject_on_worker_lost=True,  # Reject tasks if worker dies
    
    # Worker performance settings
    worker_prefetch_multiplier=4,  # Increased from 1 to 4 for better throughput
    worker_max_tasks_per_child=500,  # Reduced to prevent memory leaks
    worker_disable_rate_limits=True,  # Disable rate limits for maximum speed
    worker_pool_restarts=True,  # Enable pool restarts for stability
    
    # Connection and retry settings
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    broker_heartbeat=30,  # Heartbeat every 30 seconds
    broker_pool_limit=50,  # Increased connection pool
    
    # Result backend settings
    result_expires=3600,  # Results expire after 1 hour
    result_persistent=True,  # Persist results
    result_compression='gzip',  # Compress results to save memory
    
    # Task routing and priority
    task_default_queue='default',
    task_default_exchange='default',
    task_default_exchange_type='direct',
    task_default_routing_key='default',
    
    # Performance optimizations
    task_ignore_result=False,  # We need results for scan tracking
    task_store_eager_result=True,
    worker_send_task_events=True,  # Enable monitoring
    task_send_sent_event=True,
    
    # Memory and resource management
    worker_max_memory_per_child=200000,  # 200MB per child process
    worker_autoscaler='celery.worker.autoscale:Autoscaler',
    worker_concurrency=None,  # Let Celery decide based on CPU cores
    
    # Monitoring and logging
    worker_log_format='[%(asctime)s: %(levelname)s/%(processName)s] %(message)s',
    worker_task_log_format='[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s',
    
    # Security
    worker_hijack_root_logger=False,
    worker_log_color=False,  # Disable colors for production
)

# Advanced task routing with priorities and dedicated queues
celery_app.conf.task_routes = {
    # High-priority individual scans
    'backend.celery_tasks.scan_url_task': {
        'queue': 'scans_high',
        'priority': 9,
        'routing_key': 'scans.high'
    },
    
    # Bulk scanning with medium priority
    'backend.celery_tasks.bulk_scan_task': {
        'queue': 'scans_bulk',
        'priority': 5,
        'routing_key': 'scans.bulk'
    },
    
    # System maintenance with low priority
    'backend.celery_tasks.cleanup_old_scans': {
        'queue': 'maintenance',
        'priority': 1,
        'routing_key': 'maintenance.cleanup'
    },
    
    # Threat intelligence updates
    'backend.celery_tasks.update_threat_intel': {
        'queue': 'maintenance',
        'priority': 3,
        'routing_key': 'maintenance.intel'
    },
    
    # System health monitoring
    'backend.celery_tasks.system_health_check': {
        'queue': 'monitoring',
        'priority': 2,
        'routing_key': 'monitoring.health'
    }
}

# Queue configuration with different settings
celery_app.conf.task_queue_max_priority = 10
celery_app.conf.worker_direct = True
celery_app.conf.task_inherit_parent_priority = True

# Enhanced beat schedule with comprehensive monitoring
celery_app.conf.beat_schedule = {
    # System maintenance - every 30 minutes for faster cleanup
    'cleanup-old-scans': {
        'task': 'backend.celery_tasks.cleanup_old_scans',
        'schedule': 1800.0,  # Every 30 minutes
        'options': {'queue': 'maintenance', 'priority': 1}
    },
    
    # Threat intelligence - every hour for faster updates
    'update-threat-intelligence': {
        'task': 'backend.celery_tasks.update_threat_intel',
        'schedule': 3600.0,  # Every hour
        'options': {'queue': 'maintenance', 'priority': 3}
    },
    
    # System health monitoring - every 5 minutes
    'system-health-check': {
        'task': 'backend.celery_tasks.system_health_check',
        'schedule': 300.0,  # Every 5 minutes
        'options': {'queue': 'monitoring', 'priority': 2}
    },
    
    # Ultra-aggressive stuck scan recovery - every 15 seconds for instant recovery
    'recover-stuck-scans-ultra-aggressive': {
        'task': 'backend.celery_tasks.cleanup_old_scans',
        'schedule': 15.0,  # Every 15 seconds for instant recovery
        'options': {'queue': 'maintenance', 'priority': 9}
    }
}

# Beat scheduler settings
celery_app.conf.beat_schedule_filename = 'celerybeat-schedule'
celery_app.conf.beat_sync_every = 1  # Sync every task
celery_app.conf.beat_max_loop_interval = 5  # Check every 5 seconds
