# STEP 1: FORCE STABLE ASYNCIO LOOP (MANDATORY - MUST BE FIRST)
# This MUST be at the TOP before any other imports
import asyncio
import os
import sys

# Force asyncio to use stable event loop policy on Windows
if sys.platform == "win32":
    import asyncio

    try:
        if sys.version_info < (3, 14) and hasattr(asyncio, "WindowsProactorEventLoopPolicy"):
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:  # nosec B110
        pass

# STEP 5: DISABLE JOBLIB MULTIPROCESSING EXPLICITLY
os.environ["JOBLIB_MULTIPROCESSING"] = "0"
os.environ["LOKY_MAX_CPU_COUNT"] = "1"
os.environ["JOBLIB_VERBOSITY"] = "0"
os.environ["JOBLIB_START_METHOD"] = "spawn"  # Safer for Windows

import logging  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import traceback  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402

import uvicorn  # noqa: E402
from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402
from fastapi.middleware.trustedhost import TrustedHostMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from slowapi import Limiter, _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded  # noqa: E402

# Suppress joblib verbose output completely (BEFORE any sklearn imports)
logging.getLogger("joblib").setLevel(logging.ERROR)
logging.getLogger("sklearn").setLevel(logging.WARNING)

# Force UTF-8 encoding for Windows console to prevent Unicode errors
if sys.platform == "win32":
    import codecs  # noqa: E402

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")

# Configure logging with better performance and UTF-8 encoding
logging.basicConfig(
    level=logging.WARNING,  # Reduced from INFO to WARNING for better performance
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler("webshield.log", mode="a", encoding="utf-8")],
)
logger = logging.getLogger(__name__)

# Suppress joblib and sklearn verbose logging
logging.getLogger("joblib").setLevel(logging.ERROR)
logging.getLogger("sklearn").setLevel(logging.WARNING)
import warnings  # noqa: E402

warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*Event loop is closed.*")
warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*coroutine.*was never awaited.*")
warnings.filterwarnings("ignore", message=".*Parallel.*")

# Global crash prevention
CRASH_COUNT = 0
MAX_CRASHES = 5
SERVER_START_TIME = time.time()


# Rate limiting configuration
# Use a safe implementation of get_remote_address to avoid Windows reverse DNS lookup delays (approx 2s)
def safe_get_remote_address(request: Request):
    """Safely get remote address without triggering DNS lookups"""
    if not request.client:
        return "127.0.0.1"
    # Return the IP directly - do NOT use any function that might resolve hostname
    return request.client.host


limiter = Limiter(key_func=safe_get_remote_address)
RATE_LIMIT = "100/minute"  # Allow 100 requests per minute per IP


def safe_import(module_name, fallback=None):
    """Safely import modules with fallback"""
    try:
        return __import__(module_name)
    except Exception as e:
        logger.warning(f"Failed to import {module_name}: {e}")
        return fallback


def safe_function_call(func, *args, **kwargs):
    """Safely call functions with error isolation"""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.error(f"Function {func.__name__} failed: {e}")
        return None


# STEP 3: LOAD MODEL ONCE - Global ML engine instance
_ml_engine_instance = None
_ml_engine_lock = threading.Lock()


def _load_ml_models_once():
    """Load ML models ONCE in a thread-safe manner. Never run ML inside async directly."""
    global _ml_engine_instance

    # Double-check locking pattern for thread safety
    if _ml_engine_instance is not None:
        return _ml_engine_instance

    with _ml_engine_lock:
        if _ml_engine_instance is not None:
            return _ml_engine_instance

        try:
            logger.info("Loading ML models for the first time...")
            try:
                from ml_models.ml_integration import get_ml_engine
            except Exception:
                from .ml_models.ml_integration import get_ml_engine

            # STEP 2: NEVER run ML inside async directly
            # This runs in a separate thread, NOT in the async event loop
            _ml_engine_instance = get_ml_engine()
            logger.info("ML models loaded successfully and cached globally")

            # Update health cache after ML models are loaded
            try:
                from .api_routes import _health_cache

                if _ml_engine_instance:
                    ml_status_info = _ml_engine_instance.get_model_status()
                    _health_cache["ml_status"] = {
                        "url_classifier_trained": ml_status_info["url_classifier_trained"],
                        "content_detector_trained": ml_status_info["content_detector_trained"],
                        "models_available": ml_status_info["url_classifier_trained"]
                        or ml_status_info["content_detector_trained"],
                    }
                    _health_cache["ml_status_time"] = time.time()
                    logger.info("Health cache updated with ML status")
            except Exception as cache_error:
                logger.warning(f"Could not update health cache: {cache_error}")

            return _ml_engine_instance
        except Exception as e:
            logger.error(f"Failed to load ML models: {e}")
            logger.error(traceback.format_exc())
            return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager with crash prevention and optimized startup"""
    global CRASH_COUNT, SERVER_START_TIME

    try:
        # Startup
        logger.info("Starting WebShield server...")
        startup_start = time.time()

        # Routes are now loaded immediately after app creation for TestClient compatibility

        # Initialize database in background thread
        def init_db():
            try:
                from .db import create_database_and_tables

                env = os.getenv("ENVIRONMENT", "development").lower()
                auto_create = os.getenv("AUTO_CREATE_DB", "false").lower() in ("1", "true", "yes")
                if env in ("production", "prod") or not auto_create:
                    logger.info(
                        "AUTO_CREATE_DB disabled or production environment; skipping create_database_and_tables"
                    )
                    return
                create_database_and_tables()
                logger.info("Database initialization completed in background")
            except Exception as e:
                logger.error(f"Database initialization failed: {e}")
                logger.error(traceback.format_exc())

        # Routes are now loaded immediately after app creation for TestClient compatibility

        # STEP 3: LOAD MODEL ONCE
        # Initialize ML models in background thread pool to prevent blocking
        # Models are loaded ONCE and cached globally
        def init_ml():
            try:
                import concurrent.futures

                # Use ThreadPoolExecutor to run ML loading in a separate thread
                # This prevents blocking the async event loop
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(_load_ml_models_once)
                    # Wait max 10 seconds for ML models to load
                    try:
                        future.result(timeout=10)
                        logger.info("ML engine initialized successfully in background thread")
                    except concurrent.futures.TimeoutError:
                        logger.warning("ML engine loading timed out after 10s - will continue in background")
                    except Exception as e:
                        logger.error(f"ML initialization failed: {e}")
            except Exception as e:
                logger.error(f"ML thread pool initialization failed: {e}")
                logger.error(traceback.format_exc())

        # Start background initialization for non-critical services with timeout
        db_thread = threading.Thread(target=init_db, daemon=True)
        ml_thread = threading.Thread(target=init_ml, daemon=True)

        db_thread.start()
        ml_thread.start()

        startup_time = time.time() - startup_start
        logger.info(
            f"Server startup completed in {startup_time:.2f}s (routes loaded, services initializing in background)"
        )

        yield

    except Exception as e:
        logger.error(f"Critical server error: {e}")
        logger.error(traceback.format_exc())
        CRASH_COUNT += 1

        # Calculate uptime
        uptime = time.time() - SERVER_START_TIME

        if CRASH_COUNT >= MAX_CRASHES:
            logger.critical(
                f"Server crashed {CRASH_COUNT} times in {uptime:.1f}s. Stopping to prevent infinite crashes."
            )
            sys.exit(1)
        else:
            logger.warning(f"Server crash #{CRASH_COUNT} after {uptime:.1f}s uptime. Restarting...")
            raise
    finally:
        # Cleanup: Close any pending async tasks and sessions
        logger.info("Server shutdown initiated")
        try:
            # Give pending tasks a chance to complete
            await asyncio.sleep(0.5)

            # Cancel all pending tasks (excluding current task to prevent recursion)
            current_task = asyncio.current_task()
            tasks = [t for t in asyncio.all_tasks() if not t.done() and t is not current_task]
            if tasks:
                logger.info(f"Cancelling {len(tasks)} pending tasks...")
                for task in tasks:
                    task.cancel()
                # Wait for tasks to be cancelled
                await asyncio.gather(*tasks, return_exceptions=True)
                logger.info("All pending tasks cancelled")
        except Exception as e:
            logger.warning(f"Error during async cleanup: {e}")


# Create FastAPI app with crash prevention and rate limiting
app = FastAPI(
    title="WebShield",
    description="Advanced Web Security Scanner",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "false").lower() == "true" else None,
    redoc_url="/redoc" if os.getenv("ENABLE_DOCS", "false").lower() == "true" else None,
)

# Load routes immediately after app creation (for TestClient compatibility)
try:
    logger.info("Loading routes...")

    from .frontend_routes import frontend_router

    app.include_router(frontend_router)
    logger.info("Frontend routes loaded successfully")

    from .auth import auth_router

    app.include_router(auth_router, prefix="/api")
    logger.info("Auth routes loaded successfully")

    from .scan import scan_router

    app.include_router(scan_router, prefix="/api")
    logger.info("Scan routes loaded successfully")

    try:
        from .export import export_router

        app.include_router(export_router)
        logger.info("Export routes loaded successfully")
    except Exception as e:
        logger.warning(f"Export routes failed to load: {e}")
        # Continue without export routes

    from .api_routes import api_router, health_router

    app.include_router(api_router, prefix="/api")
    app.include_router(health_router, prefix="/api")
    logger.info("API routes loaded successfully")

    try:
        from .translation_routes import translation_router

        app.include_router(translation_router)
        logger.info("Translation routes loaded successfully")
    except Exception as e:
        logger.warning(f"Translation routes failed to load: {e}")
        # Continue without translation routes

    try:
        from .chatbot_routes import chatbot_router

        app.include_router(chatbot_router)
        logger.info("Chatbot routes loaded successfully")
    except Exception as e:
        logger.warning(f"Chatbot routes failed to load: {e}")
        # Continue without chatbot routes

    # Email scanning routes for Gmail extension
    try:
        from .email_routes import email_router

        app.include_router(email_router, prefix="/api")
        logger.info("Email routes loaded successfully")
    except Exception as e:
        logger.warning(f"Email routes failed to load: {e}")
        # Continue without email routes

    # Course routes for educational platform
    try:
        from .courses.routes import course_router

        app.include_router(course_router)
        logger.info("Course routes loaded successfully")
    except Exception as e:
        logger.warning(f"Course routes failed to load: {e}")
        # Continue without course routes

    logger.info("All routes loaded successfully")
except Exception as e:
    logger.error(f"Failed to load routes: {e}")
    logger.error(traceback.format_exc())

# Add rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Add global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler to prevent crashes"""
    logger.error(f"Unhandled exception: {exc}")
    logger.error(f"Request: {request.method} {request.url}")
    logger.error(traceback.format_exc())

    # Return a safe error response instead of crashing
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again.",
        },
    )


# Add middleware with error handling and performance optimizations
@app.middleware("http")
async def crash_prevention_middleware(request: Request, call_next):
    """Middleware to catch and handle any unhandled errors with performance optimizations"""
    start_time = time.time()

    try:
        # Add request timeout protection
        try:
            response = await asyncio.wait_for(call_next(request), timeout=10.0)  # Reduced to 10s to prevent crashes

            # Add response time logging for performance monitoring
            process_time = time.time() - start_time
            if process_time > 1.0:  # Log slow requests
                logger.warning(f"Slow request: {request.method} {request.url} took {process_time:.2f}s")

            return response
        except asyncio.TimeoutError:
            logger.error(f"Request timeout for {request.method} {request.url}")
            return JSONResponse(
                status_code=408,
                content={
                    "error": "Request timeout",
                    "message": "The request took too long to process. Please try again.",
                },
            )

    except Exception as e:
        logger.error(f"Middleware caught error: {e}")
        logger.error(f"Request: {request.method} {request.url}")
        logger.error(traceback.format_exc())

        # Return safe error response
        return JSONResponse(
            status_code=500,
            content={
                "error": "Request processing error",
                "message": "The request could not be processed. Please try again.",
            },
        )


# Add CORS middleware with production-ready settings
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
_allowed_origins_raw = os.getenv("ALLOWED_ORIGINS", "*")
ALLOWED_ORIGINS = [o.strip() for o in _allowed_origins_raw.split(",") if o.strip()]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["*"]

# In production, do not allow credentialed CORS with wildcard origins.
# Require explicit origin allowlist via ALLOWED_ORIGINS.
if ENVIRONMENT in ("production", "prod") and ALLOWED_ORIGINS == ["*"]:
    logger.warning("ALLOWED_ORIGINS is '*' in production; disabling allow_credentials for safety")
    _allow_credentials = False
else:
    _allow_credentials = True
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS != ["*"] else ["*"],
    allow_credentials=_allow_credentials,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
    expose_headers=["X-Request-ID", "X-Response-Time"],
)

# Add GZip middleware with optimized settings
app.add_middleware(GZipMiddleware, minimum_size=500)  # Reduced from 1000 to 500 bytes

# Add trusted host middleware for security
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
# Add testserver for testing compatibility
if "testserver" not in ALLOWED_HOSTS and ALLOWED_HOSTS != ["*"]:
    ALLOWED_HOSTS.append("testserver")
app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS if ALLOWED_HOSTS != ["*"] else ["*"])


# Add security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses"""
    import uuid

    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id

    response = await call_next(request)

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Request ID for tracing (stable for request)
    response.headers["X-Request-ID"] = request_id

    return response


# Add rate-limited endpoints for heavy operations
@app.get("/api/scan/status/{scan_id}")
@limiter.limit(RATE_LIMIT)
async def get_scan_status(request: Request, scan_id: str):
    """Get scan status with rate limiting"""
    try:
        from .scan import get_scan_status

        return await get_scan_status(scan_id)
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan status") from e



# Mount logos directory for collaboration logos
if os.path.isdir("logos"):
    app.mount("/logos", StaticFiles(directory="logos"), name="logos")

if os.path.isdir("frontend"):
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

if __name__ == "__main__":
    try:

        # Optimized uvicorn configuration for better performance
        uvicorn.run(
            "backend.server:app",
            host="0.0.0.0",  # nosec B104
            port=8000,
            reload=False,
            log_level="warning",
            access_log=False,
            http="h11",
            workers=1,
            loop="asyncio",
            limit_concurrency=100,
            limit_max_requests=1000,
            timeout_keep_alive=5,
            timeout_graceful_shutdown=10,
        )
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)
