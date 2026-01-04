# -*- coding: utf-8 -*-
import logging
import os
import threading
import time
from contextlib import contextmanager
from urllib.parse import urlparse

import mysql.connector
from dotenv import load_dotenv
from fastapi import APIRouter
from mysql.connector import Error, pooling

logger = logging.getLogger(__name__)

load_dotenv()

# Global connection pool
_connection_pool = None
_pool_lock = threading.Lock()
_pool_initialized = False

# Pooling defaults: allow override via env; default-disable on Windows for stability
_pool_disabled_env = os.getenv("DB_DISABLE_POOL")
_pool_disabled = (_pool_disabled_env.lower() in ("1", "true", "yes")) if _pool_disabled_env else (os.name == "nt")


def _build_mysql_config():
    """Build MySQL configuration strictly from environment variables (or DB_URL)."""
    import os

    from dotenv import load_dotenv

    load_dotenv()

    # Optional consolidated URL: mysql://user:pass@host:port/dbname
    db_url = os.getenv("DB_URL")
    host = None
    port = None
    user = None
    password = None
    database = None

    if db_url:
        try:
            parsed = urlparse(db_url)
            if parsed.scheme.startswith("mysql"):
                host = parsed.hostname
                port = parsed.port
                user = parsed.username
                password = parsed.password
                if parsed.path and parsed.path != "/":
                    database = parsed.path.lstrip("/")
        except Exception:  # nosec B110
            pass

    # Fallback to individual env vars when DB_URL not fully specified
    host = host or os.getenv("DB_HOST")
    db_port_str = os.getenv("DB_PORT")
    port = port or (int(db_port_str) if db_port_str else None)
    user = user or os.getenv("DB_USER")
    password = password or os.getenv("DB_PASSWORD")
    database = database or os.getenv("DB_NAME")

    missing = []
    if not host:
        missing.append("DB_HOST")
    if not user:
        missing.append("DB_USER")
    if password is None:
        missing.append("DB_PASSWORD")  # require explicit value (can be empty string only if intended)
    if not database:
        missing.append("DB_NAME")

    if missing:
        logger.error(f"Database configuration missing required env vars: {', '.join(missing)}")
        logger.error("Please create a .env file with database credentials (see env_template.txt for example)")
        logger.error("Or set environment variables: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME")
        # Provide default values for development
        if "DB_HOST" in missing:
            host = "127.0.0.1"
        if "DB_USER" in missing:
            user = "root"
        if "DB_PASSWORD" in missing:
            password = ""  # nosec B105
        if "DB_NAME" in missing:
            database = "webshield"
        logger.warning(f"Using default database configuration: {user}@{host}:{port or 3306}/{database}")
        logger.warning("This may fail if your database is not configured with these defaults")

    # Optimized configuration for better performance
    config = {
        "host": host,
        "port": port or 3306,
        "user": user,
        "password": password,
        "database": database,
        "charset": "utf8mb4",
        "collation": "utf8mb4_unicode_ci",
        "autocommit": True,
        "pool_name": "webshield_pool",
        "pool_size": 5,  # Reduced to 5 to prevent connection exhaustion
        "pool_reset_session": True,
        "get_warnings": False,  # Disabled for better performance
        "raise_on_warnings": False,
        "connection_timeout": 10,  # Reduced from 30 to 10 seconds
        "use_pure": True,  # Use pure Python to avoid missing C extension issues
        "sql_mode": "STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO",
        "init_command": 'SET SESSION sql_mode="STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO"',
        "buffered": True,  # Use buffered cursors for better performance
        "raw": False,
        "consume_results": True,
        "client_flags": [mysql.connector.ClientFlag.MULTI_STATEMENTS],
    }

    # SSL handling
    ssl_mode = os.getenv("DB_SSL_MODE", "DISABLED")
    if ssl_mode == "REQUIRED":
        config["ssl_disabled"] = False
        if os.getenv("DB_SSL_CA"):
            config["ssl_ca"] = os.getenv("DB_SSL_CA")
        if os.getenv("DB_SSL_CERT"):
            config["ssl_cert"] = os.getenv("DB_SSL_CERT")
        if os.getenv("DB_SSL_KEY"):
            config["ssl_key"] = os.getenv("DB_SSL_KEY")
    else:
        config["ssl_disabled"] = True

    return config


def _initialize_connection_pool():
    """Initialize the connection pool with retry logic.
    Never raises. On failure, marks pool as initialized-disabled and returns None so callers can fall back to direct connections.
    """
    global _connection_pool, _pool_initialized, _pool_disabled

    if _pool_initialized:
        return _connection_pool

    # Allow disabling pool via env (safer on Windows and when C extension is unavailable)
    if _pool_disabled:
        logger.warning("Database connection pooling is disabled via DB_DISABLE_POOL")
        with _pool_lock:
            _connection_pool = None
            _pool_initialized = True
        return None

    with _pool_lock:
        if _pool_initialized:  # Double-check pattern
            return _connection_pool

        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            try:
                config = _build_mysql_config()
                logger.info(f"Initializing connection pool (attempt {attempt + 1})")

                _connection_pool = pooling.MySQLConnectionPool(**config)

                # Test the pool
                test_conn = _connection_pool.get_connection()
                test_conn.ping(reconnect=True)
                test_conn.close()

                _pool_initialized = True
                logger.info("Connection pool initialized successfully")
                return _connection_pool

            except Exception as e:
                logger.error(f"Connection pool initialization failed (attempt {attempt + 1}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error(
                        "Failed to initialize connection pool after all attempts; falling back to direct connections"
                    )
                    _connection_pool = None
                    _pool_initialized = True
                    return None


def get_mysql_connection():
    """Get a database connection with comprehensive error handling and graceful fallback."""
    global _pool_initialized, _connection_pool

    try:
        # Initialize pool if needed (will not raise)
        if not _pool_initialized:
            _initialize_connection_pool()

        # Prefer pool if available
        if _connection_pool is not None:
            try:
                conn = _connection_pool.get_connection()
                if conn and conn.is_connected():
                    conn.ping(reconnect=True)
                    return conn
                else:
                    logger.warning("Pool returned invalid connection, will try direct connection")
            except Exception as pool_error:
                logger.warning(f"Pool connection failed: {pool_error}")

        # Fallback to direct connection in all cases where pool is unavailable or failed
        config = _build_mysql_config()
        config.pop("pool_name", None)
        config.pop("pool_size", None)
        config.pop("pool_reset_session", None)
        config.pop("pool_recycle", None)

        conn_result = mysql.connector.connect(**config)
        conn = conn_result  # type: ignore[assignment]
        if conn and conn.is_connected():
            conn.ping(reconnect=True)
            logger.info("Direct connection established successfully")
            return conn
        else:
            logger.error("Direct connection failed")
            return None

    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None


@contextmanager
def get_db_connection_with_retry(max_retries=3, delay=1):
    """Context manager for database connections with retry logic.
    Usage:
        with get_db_connection_with_retry() as conn:
            if conn:
                # use conn.cursor() ...
    DO NOT use: conn = get_db_connection_with_retry()  # This returns a context manager, not a connection!
    """
    conn = None
    for attempt in range(max_retries):
        try:
            conn = get_mysql_connection()
            if conn and conn.is_connected():
                try:
                    yield conn
                finally:
                    # Always close the connection when exiting the context
                    if conn and conn.is_connected():
                        conn.close()
                        logger.debug("Database connection closed successfully")
                return
            else:
                logger.warning(f"Database connection attempt {attempt + 1} failed")
        except Exception as e:
            logger.warning(f"Database connection error on attempt {attempt + 1}: {e}")
            if conn and conn.is_connected():
                conn.close()

        if attempt < max_retries - 1:
            time.sleep(delay)
            delay *= 1.5  # Progressive delay

    # If all retries failed, yield None
    logger.error("All database connection attempts failed")
    yield None


# Helper for legacy code that expects a direct connection (not recommended for new code)
def get_db_connection_with_retry_direct(max_retries=3, delay=1):
    """
    Returns a connection directly (not a context manager).
    Use only if you cannot use 'with' statement.
    """
    for _attempt in range(max_retries):
        conn = get_mysql_connection()
        if conn and conn.is_connected():
            return conn
        time.sleep(delay)
        delay *= 1.5
    return None


def execute_db_operation(operation_func, *args, **kwargs):
    """
    Safely execute a database operation with automatic connection management.

    Args:
        operation_func: Function that takes a connection and performs the operation
        *args, **kwargs: Arguments to pass to the operation function

    Returns:
        Result of the operation function or None if failed
    """
    conn = None
    try:
        conn = get_mysql_connection()
        if not conn:
            logger.error("Cannot execute operation: no connection available")
            return None

        result = operation_func(conn, *args, **kwargs)
        return result

    except Exception as e:
        logger.error(f"Database operation error: {e}")
        return None
    finally:
        if conn and conn.is_connected():
            try:
                conn.close()
                logger.debug("Database connection closed after operation")
            except Exception as close_error:
                logger.warning(f"Error closing database connection: {close_error}")


def create_database_and_tables():
    """Create database and tables with comprehensive error handling"""
    try:
        env = os.getenv("ENVIRONMENT", "development").lower()
        auto_create = os.getenv("AUTO_CREATE_DB", "false").lower() in ("1", "true", "yes")
        if env in ("production", "prod") or not auto_create:
            logger.warning("Skipping create_database_and_tables (AUTO_CREATE_DB disabled or production)")
            return False
        conn = get_mysql_connection()
        if not conn:
            logger.error("Cannot create database: no connection available")
            return False

        cursor = conn.cursor()

        try:
            # Create database if it doesn't exist
            import os as _os

            db_name = _os.getenv("DB_NAME", "webshield")
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
            cursor.execute(f"USE `{db_name}`")

            # Create users table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    last_login TIMESTAMP NULL,
                    profile_picture VARCHAR(255),
                    is_admin BOOLEAN DEFAULT FALSE,
                    api_key VARCHAR(255),
                    api_settings JSON
                )
            """
            )

            # Create scans table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    scan_id VARCHAR(255) UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    status ENUM('processing', 'completed', 'failed') DEFAULT 'processing',
                    is_malicious BOOLEAN DEFAULT FALSE,
                    threat_level ENUM('low', 'medium', 'high', 'moderate', 'unknown') DEFAULT 'low',
                    malicious_count INT DEFAULT 0,
                    suspicious_count INT DEFAULT 0,
                    total_engines INT DEFAULT 0,
                    ssl_valid BOOLEAN DEFAULT FALSE,
                    domain_reputation ENUM('clean', 'suspicious', 'malicious', 'unknown') DEFAULT 'unknown',
                    detection_details JSON,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP NULL,
                    scan_timestamp TIMESTAMP NULL,
                    user_email VARCHAR(255),
                    INDEX idx_scan_id (scan_id),
                    INDEX idx_user_email (user_email),
                    INDEX idx_created_at (created_at)
                )
            """
            )

            # Create reports table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    report_type ENUM('blacklist', 'whitelist') NOT NULL,
                    url TEXT NOT NULL,
                    reason TEXT,
                    user_email VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status ENUM('pending', 'approved', 'rejected') DEFAULT 'pending',
                    INDEX idx_user_email (user_email),
                    INDEX idx_report_type (report_type),
                    INDEX idx_status (status)
                )
            """
            )

            # Create ML model training statistics table
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

            # Insert default ML training statistics if table is empty
            cursor.execute("SELECT COUNT(*) as count FROM ml_training_stats")
            ml_stats_result = cursor.fetchone()
            ml_stats_count = ml_stats_result[0] if ml_stats_result else 0

            if ml_stats_count == 0:
                # Insert default values based on typical Kaggle dataset sizes
                cursor.execute(
                    """
                    INSERT INTO ml_training_stats
                    (model_name, dataset_name, total_urls_trained, malicious_urls_count, benign_urls_count, model_version, accuracy_score)
                    VALUES
                    ('URL Threat Classifier', 'Kaggle Malicious URLs Dataset', 450000, 225000, 225000, '1.0', 0.95),
                    ('Content Phishing Detector', 'Kaggle Malicious URLs Dataset', 450000, 225000, 225000, '1.0', 0.92)
                """
                )
                logger.info("Inserted default ML training statistics")

            # Create courses table for the learning platform
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS courses (
                    course_id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    difficulty_level ENUM('beginner', 'intermediate', 'advanced') DEFAULT 'beginner',
                    duration_minutes INT DEFAULT 60,
                    thumbnail_url VARCHAR(500),
                    instructor_name VARCHAR(100) DEFAULT 'WebShield Team',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    is_published BOOLEAN DEFAULT TRUE,
                    enrollment_count INT DEFAULT 0,
                    rating DECIMAL(3,2) DEFAULT 4.50,
                    category VARCHAR(50) DEFAULT 'security',
                    INDEX idx_difficulty (difficulty_level),
                    INDEX idx_published (is_published)
                )
            """
            )

            # Create course modules table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS course_modules (
                    module_id VARCHAR(36) PRIMARY KEY,
                    course_id VARCHAR(36) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    description TEXT,
                    order_index INT DEFAULT 0,
                    FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE CASCADE,
                    INDEX idx_course_modules_course (course_id)
                )
            """
            )

            # Create lessons table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS lessons (
                    lesson_id VARCHAR(36) PRIMARY KEY,
                    module_id VARCHAR(36) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    content_type ENUM('video', 'text', 'interactive', 'quiz') DEFAULT 'text',
                    content LONGTEXT,
                    video_url VARCHAR(500),
                    duration_minutes INT DEFAULT 10,
                    order_index INT DEFAULT 0,
                    FOREIGN KEY (module_id) REFERENCES course_modules(module_id) ON DELETE CASCADE,
                    INDEX idx_lessons_module (module_id)
                )
            """
            )

            # Create user enrollments table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS user_enrollments (
                    enrollment_id VARCHAR(36) PRIMARY KEY,
                    user_email VARCHAR(255) NOT NULL,
                    course_id VARCHAR(36) NOT NULL,
                    enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP NULL,
                    progress_percentage DECIMAL(5,2) DEFAULT 0.00,
                    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE CASCADE,
                    INDEX idx_enrollments_user (user_email),
                    INDEX idx_enrollments_course (course_id),
                    UNIQUE KEY unique_enrollment (user_email, course_id)
                )
            """
            )

            # Create lesson progress table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS lesson_progress (
                    progress_id VARCHAR(36) PRIMARY KEY,
                    user_email VARCHAR(255) NOT NULL,
                    lesson_id VARCHAR(36) NOT NULL,
                    completed BOOLEAN DEFAULT FALSE,
                    completed_at TIMESTAMP NULL,
                    time_spent_seconds INT DEFAULT 0,
                    quiz_score DECIMAL(5,2) NULL,
                    notes TEXT,
                    FOREIGN KEY (lesson_id) REFERENCES lessons(lesson_id) ON DELETE CASCADE,
                    INDEX idx_progress_user (user_email),
                    INDEX idx_progress_lesson (lesson_id),
                    UNIQUE KEY unique_progress (user_email, lesson_id)
                )
            """
            )

            # Create quiz questions table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS quiz_questions (
                    question_id VARCHAR(36) PRIMARY KEY,
                    lesson_id VARCHAR(36) NOT NULL,
                    question_text TEXT NOT NULL,
                    question_type ENUM('multiple_choice', 'true_false', 'fill_blank') DEFAULT 'multiple_choice',
                    correct_answer TEXT,
                    explanation TEXT,
                    points INT DEFAULT 1,
                    order_index INT DEFAULT 0,
                    FOREIGN KEY (lesson_id) REFERENCES lessons(lesson_id) ON DELETE CASCADE,
                    INDEX idx_questions_lesson (lesson_id)
                )
            """
            )

            # Create quiz options table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS quiz_options (
                    option_id VARCHAR(36) PRIMARY KEY,
                    question_id VARCHAR(36) NOT NULL,
                    option_text TEXT NOT NULL,
                    is_correct BOOLEAN DEFAULT FALSE,
                    order_index INT DEFAULT 0,
                    FOREIGN KEY (question_id) REFERENCES quiz_questions(question_id) ON DELETE CASCADE,
                    INDEX idx_options_question (question_id)
                )
            """
            )

            # Create achievements table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS achievements (
                    achievement_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    description TEXT,
                    icon VARCHAR(100) DEFAULT '🏆',
                    points INT DEFAULT 10,
                    category VARCHAR(50)
                )
            """
            )

            # Create user achievements table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS user_achievements (
                    user_achievement_id VARCHAR(36) PRIMARY KEY,
                    user_email VARCHAR(255) NOT NULL,
                    achievement_id VARCHAR(36) NOT NULL,
                    earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (achievement_id) REFERENCES achievements(achievement_id) ON DELETE CASCADE,
                    INDEX idx_user_achievements_user (user_email),
                    UNIQUE KEY unique_user_achievement (user_email, achievement_id)
                )
            """
            )

            # Create certificates table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS certificates (
                    certificate_id VARCHAR(36) PRIMARY KEY,
                    user_email VARCHAR(255) NOT NULL,
                    course_id VARCHAR(36) NOT NULL,
                    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    certificate_url VARCHAR(500),
                    verification_code VARCHAR(50) UNIQUE,
                    FOREIGN KEY (course_id) REFERENCES courses(course_id) ON DELETE CASCADE,
                    INDEX idx_certificates_user (user_email)
                )
            """
            )

            logger.info("Course system tables created successfully")

            # Insert sample courses if table is empty
            cursor.execute("SELECT COUNT(*) as count FROM courses")
            courses_count = cursor.fetchone()[0]

            if courses_count == 0:
                # Insert sample courses
                cursor.execute(
                    """
                    INSERT INTO courses (course_id, title, description, difficulty_level, duration_minutes, instructor_name, enrollment_count, rating) VALUES
                    -- Beginner Courses
                    ('c1', 'Introduction to Cyber Security', 'Learn the fundamental concepts of cybersecurity, including threats, vulnerabilities, and basic protection techniques.', 'beginner', 120, 'WebShield Security Team', 5420, 4.8),
                    ('c2', 'Ethical Hacking', 'Discover the world of ethical hacking. Learn penetration testing, vulnerability assessment, and security testing methodologies.', 'beginner', 90, 'WebShield Security Team', 3890, 4.9),
                    ('c3', 'Cryptography', 'Understand encryption, decryption, hashing, and cryptographic protocols to secure data and communications.', 'beginner', 150, 'WebShield Security Team', 2150, 4.7),
                    ('c4', 'Threats to Websites', 'Learn about common web threats including SQL injection, XSS, CSRF, and how to protect your websites from attacks.', 'beginner', 60, 'WebShield Security Team', 4200, 4.6),
                    -- Intermediate Courses
                    ('c5', 'Phishing Attacks', 'Master the identification and prevention of phishing attacks. Learn about email phishing, spear phishing, and social engineering tactics.', 'intermediate', 100, 'WebShield Security Team', 2850, 4.7),
                    ('c6', 'Kali Linux Fundamentals', 'Get hands-on with Kali Linux, the leading platform for penetration testing and security auditing.', 'intermediate', 180, 'WebShield Security Team', 3200, 4.8),
                    ('c7', 'Wire Shark for Network Monitoring', 'Learn to use Wireshark for network protocol analysis, packet capture, and traffic monitoring.', 'intermediate', 120, 'WebShield Security Team', 2650, 4.6),
                    -- Advanced Courses
                    ('c8', 'Introduction to System Security', 'Advanced course on operating system security, hardening techniques, and system-level protection mechanisms.', 'advanced', 200, 'WebShield Security Team', 1420, 4.9),
                    ('c9', 'Protection from Browser Attacks', 'In-depth analysis of browser vulnerabilities, XSS, CSRF, clickjacking, and advanced browser security techniques.', 'advanced', 150, 'WebShield Security Team', 1650, 4.8),
                    ('c10', 'Securing Android Devices', 'Comprehensive guide to Android security, app permissions, malware detection, and mobile device hardening.', 'advanced', 180, 'WebShield Security Team', 1890, 4.7)
                """
                )
                logger.info("Inserted sample courses")

                # Insert sample achievements
                cursor.execute(
                    """
                    INSERT INTO achievements (achievement_id, name, description, icon, points, category) VALUES
                    ('a1', 'First Steps', 'Enrolled in your first course', '[LEARN]', 10, 'learning'),
                    ('a2', 'Quick Learner', 'Complete your first lesson', '📚', 15, 'learning'),
                    ('a3', 'Quiz Master', 'Score 100%% on a quiz', '💯', 25, 'assessment'),
                    ('a4', 'Course Crusher', 'Complete your first course', '🏆', 50, 'learning'),
                    ('a5', 'Security Sentinel', 'Scan 10 URLs', '[SHIELD]', 15, 'scanning'),
                    ('a6', 'Threat Hunter', 'Identify 5 malicious URLs', '[SEARCH]', 30, 'scanning'),
                    ('a7', 'Learning Streak', 'Learn for 7 days in a row', '🔥', 40, 'engagement'),
                    ('a8', 'Perfect Score', 'Get 100%% on all quizzes in a course', '⭐', 75, 'assessment')
                """
                )
                logger.info("Inserted sample achievements")

            # Add user_email column to existing scans table if it doesn't exist
            try:
                cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
                logger.info("Added user_email column to scans table")
            except Error as e:
                if "Duplicate column name" in str(e):
                    logger.info("user_email column already exists in scans table")
                else:
                    logger.error(f"Error adding user_email column: {e}")

            # Migrate threat_level column to support new values (moderate, unknown)
            try:
                cursor.execute(
                    """
                    ALTER TABLE scans
                    MODIFY COLUMN threat_level ENUM('low', 'medium', 'high', 'moderate', 'unknown') DEFAULT 'low'
                """
                )
                logger.info("Updated threat_level column to support all threat levels")
            except Error as e:
                if "Duplicate" in str(e) or "same" in str(e).lower():
                    logger.info("threat_level column already has correct ENUM values")
                else:
                    logger.warning(f"Could not update threat_level column: {e}")

            # Add last_login column to users table if it doesn't exist
            try:
                cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP NULL")
                logger.info("Added last_login column to users table")
            except Error as e:
                if "Duplicate column name" in str(e):
                    logger.info("last_login column already exists in users table")
                else:
                    logger.error(f"Error adding last_login column: {e}")

            # Add indexes if they don't exist
            try:
                cursor.execute("CREATE INDEX idx_user_email ON scans(user_email)")
                logger.info("Added user_email index to scans table")
            except Error as e:
                if "Duplicate key name" in str(e):
                    logger.info("user_email index already exists")
                else:
                    logger.error(f"Error adding user_email index: {e}")

            conn.commit()
            logger.info("Database and tables created successfully")
            return True

        except Error as e:
            logger.error(f"Database creation error: {e}")
            conn.rollback()
            return False
        finally:
            cursor.close()
            try:
                if conn:
                    conn.close()
            except Exception:  # nosec B110
                pass

    except Exception as e:
        logger.error(f"Critical database error: {e}")
        return False


db_router = APIRouter(prefix="/api", tags=["Database"])


def get_pool_status():
    """Get current connection pool status for monitoring"""
    global _connection_pool, _pool_initialized

    if not _pool_initialized or not _connection_pool:
        return {
            "pool_initialized": False,
            "pool_size": 0,
            "active_connections": 0,
            "available_connections": 0,
            "status": "not_initialized",
        }

    try:
        # Get pool configuration
        pool_config = _connection_pool._cnx_queue.maxsize
        active_connections = pool_config - _connection_pool._cnx_queue.qsize()
        available_connections = _connection_pool._cnx_queue.qsize()

        return {
            "pool_initialized": True,
            "pool_size": pool_config,
            "active_connections": active_connections,
            "available_connections": available_connections,
            "utilization_percent": round((active_connections / pool_config) * 100, 2),
            "status": "healthy" if available_connections > 0 else "exhausted",
        }
    except Exception as e:
        logger.error(f"Error getting pool status: {e}")
        return {
            "pool_initialized": _pool_initialized,
            "pool_size": 0,
            "active_connections": 0,
            "available_connections": 0,
            "status": "error",
            "error": str(e),
        }


async def startup_event():
    import threading

    def init_db():
        try:
            create_database_and_tables()
        except Exception:  # nosec B110
            pass

    threading.Thread(target=init_db, daemon=True).start()


def check_database_health():
    """Check database connectivity and health"""
    result = {"status": "unknown", "pool_status": get_pool_status()}

    conn = None
    try:
        conn = get_mysql_connection()
        if conn and conn.is_connected():
            result["status"] = "healthy"
            result["message"] = "Database connection successful"
            return result
        else:
            result["status"] = "unhealthy"
            result["message"] = "Could not establish database connection"
            return result
    except Exception as e:
        result["status"] = "error"
        result["message"] = str(e)
        return result
    finally:
        if conn and conn.is_connected():
            try:
                conn.close()
            except Exception as e:
                logger.warning(f"Failed to close DB connection during health check: {e}")
