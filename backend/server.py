from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import uvicorn
import logging
import threading
import time
import sys
import traceback
import asyncio
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

# Configure logging with better performance
logging.basicConfig(
    level=logging.WARNING,  # Reduced from INFO to WARNING for better performance
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('webshield.log', mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# Global crash prevention
CRASH_COUNT = 0
MAX_CRASHES = 5
SERVER_START_TIME = time.time()

# Rate limiting configuration
limiter = Limiter(key_func=get_remote_address)
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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager with crash prevention and optimized startup"""
    global CRASH_COUNT, SERVER_START_TIME
    
    try:
        # Startup
        logger.info("Starting WebShield server...")
        startup_start = time.time()
        
        # Load routes immediately (not in background)
        try:
            logger.info("Loading routes...")
            
            logger.info("Importing frontend_routes...")
            from .frontend_routes import frontend_router
            logger.info("Frontend routes imported successfully")
            app.include_router(frontend_router)
            logger.info("Frontend routes loaded successfully")
            
            logger.info("Importing auth...")
            from .auth import auth_router
            logger.info("Auth imported successfully")
            app.include_router(auth_router, prefix="/api")
            logger.info("Auth routes loaded successfully")
            
            logger.info("Importing scan...")
            from .scan import scan_router
            logger.info("Scan imported successfully")
            app.include_router(scan_router, prefix="/api")
            logger.info("Scan routes loaded successfully")
            
            logger.info("Importing api_routes...")
            from .api_routes import api_router
            logger.info("API routes imported successfully")
            app.include_router(api_router, prefix="/api")
            logger.info("API routes loaded successfully")
            
            logger.info("All routes loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load routes: {e}")
            logger.error(traceback.format_exc())
            # Don't crash the server if routes fail to load
        
        # Initialize other services in background threads with timeout
        def init_db():
            try:
                from .db import create_database_and_tables
                create_database_and_tables()
                logger.info("Database initialization completed in background")
            except Exception as e:
                logger.error(f"Database initialization failed: {e}")
                logger.error(traceback.format_exc())
        
        def init_ml():
            try:
                try:
                    from ml_models.ml_integration import get_ml_engine as top_get_ml
                    top_get_ml()
                except Exception:
                    from .ml_models.ml_integration import get_ml_engine as backend_get_ml
                    backend_get_ml()
                logger.info("ML engine initialized in background")
            except Exception as e:
                logger.error(f"ML initialization failed: {e}")
                logger.error(traceback.format_exc())
        
        # Start background initialization for non-critical services with timeout
        db_thread = threading.Thread(target=init_db, daemon=True)
        ml_thread = threading.Thread(target=init_ml, daemon=True)
        
        db_thread.start()
        ml_thread.start()
        
        # Wait for critical services with timeout
        db_thread.join(timeout=10)  # Wait max 10 seconds for DB
        ml_thread.join(timeout=15)  # Wait max 15 seconds for ML
        
        startup_time = time.time() - startup_start
        logger.info(f"Server startup completed in {startup_time:.2f}s (routes loaded, services initializing in background)")
        
        yield
        
    except Exception as e:
        logger.error(f"Critical server error: {e}")
        logger.error(traceback.format_exc())
        CRASH_COUNT += 1
        
        # Calculate uptime
        uptime = time.time() - SERVER_START_TIME
        
        if CRASH_COUNT >= MAX_CRASHES:
            logger.critical(f"Server crashed {CRASH_COUNT} times in {uptime:.1f}s. Stopping to prevent infinite crashes.")
            sys.exit(1)
        else:
            logger.warning(f"Server crash #{CRASH_COUNT} after {uptime:.1f}s uptime. Restarting...")
            raise
    finally:
        logger.info("Server shutdown initiated")

# Create FastAPI app with crash prevention and rate limiting
app = FastAPI(
    title="WebShield",
    description="Advanced Web Security Scanner",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "false").lower() == "true" else None,
    redoc_url="/redoc" if os.getenv("ENABLE_DOCS", "false").lower() == "true" else None
)

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
    return {
        "error": "Internal server error",
        "message": "An unexpected error occurred. Please try again.",
        "status_code": 500
    }

# Add middleware with error handling and performance optimizations
@app.middleware("http")
async def crash_prevention_middleware(request: Request, call_next):
    """Middleware to catch and handle any unhandled errors with performance optimizations"""
    start_time = time.time()
    
    try:
        # Add request timeout protection
        try:
            response = await asyncio.wait_for(call_next(request), timeout=15.0)  # Reduced from 30s to 15s
            
            # Add response time logging for performance monitoring
            process_time = time.time() - start_time
            if process_time > 1.0:  # Log slow requests
                logger.warning(f"Slow request: {request.method} {request.url} took {process_time:.2f}s")
            
            return response
        except asyncio.TimeoutError:
            logger.error(f"Request timeout for {request.method} {request.url}")
            return {
                "error": "Request timeout",
                "message": "The request took too long to process. Please try again.",
                "status_code": 408
            }
            
    except Exception as e:
        logger.error(f"Middleware caught error: {e}")
        logger.error(f"Request: {request.method} {request.url}")
        logger.error(traceback.format_exc())
        
        # Return safe error response
        return {
            "error": "Request processing error",
            "message": "The request could not be processed. Please try again.",
            "status_code": 500
        }

# Add CORS middleware with optimized settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this to specific domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,  # Cache preflight requests for 1 hour
)

# Add GZip middleware with optimized settings
app.add_middleware(GZipMiddleware, minimum_size=500)  # Reduced from 1000 to 500 bytes

# Add trusted host middleware for security
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["*"]  # In production, restrict this to specific domains
)

# Add a basic health check endpoint that doesn't require any imports
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "WebShield server is running"}

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
        raise HTTPException(status_code=500, detail="Failed to get scan status")

# Startup event to initialize services in background
@app.on_event("startup")
async def startup_event():
    """Startup event - services are initialized in background threads"""
    pass

if __name__ == "__main__":
    try:
        # Optimized uvicorn configuration for better performance
        uvicorn.run(
            "backend.server:app",
            host="0.0.0.0",
            port=8000,
            reload=False,  # Disable reload for production
            log_level="warning",  # Reduced logging for better performance
            access_log=False,  # Disable access logs for better performance
            http="h11",  # Force pure Python HTTP implementation for Windows stability
            workers=1,  # Single worker for development, increase for production
            loop="asyncio",  # Use asyncio event loop
            limit_concurrency=100,  # Limit concurrent connections
            limit_max_requests=1000,  # Restart worker after 1000 requests
            timeout_keep_alive=5,  # Reduce keep-alive timeout
            timeout_graceful_shutdown=10,  # Graceful shutdown timeout
        )
    except Exception as e:
        logger.error(f"Server startup failed: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)