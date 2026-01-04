# Production-Ready Dockerfile with Multi-Stage Build
# Optimized for security, size, and performance

# Stage 1: Base image with dependencies
FROM python:3.11-slim-bullseye AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Create non-root user for security
RUN groupadd -r webshield && useradd -r -g webshield webshield

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Dependencies installation
FROM base AS dependencies

WORKDIR /app

# Copy requirements files
COPY requirements-runtime.txt requirements-ml.txt requirements-production.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements-runtime.txt && \
    pip install --no-cache-dir -r requirements-ml.txt && \
    pip install --no-cache-dir -r requirements-production.txt

# Stage 3: Production image
FROM base AS production

WORKDIR /app

# Copy installed dependencies from previous stage
COPY --from=dependencies /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=dependencies /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=webshield:webshield . .

# Create necessary directories
RUN mkdir -p /app/logs /app/uploads /app/tmp && \
    chown -R webshield:webshield /app

# Remove unnecessary files
RUN find /app -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true && \
    find /app -type f -name "*.pyc" -delete && \
    find /app -type f -name "*.pyo" -delete && \
    rm -rf /app/.git /app/tests /app/.pytest_cache

# Switch to non-root user
USER webshield

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose port
EXPOSE 8000

# Set production environment
ENV ENVIRONMENT=production \
    PYTHONPATH=/app

# Run application with gunicorn for production
CMD ["gunicorn", "backend.server:app", \
    "--bind", "0.0.0.0:8000", \
    "--workers", "4", \
    "--worker-class", "uvicorn.workers.UvicornWorker", \
    "--access-logfile", "-", \
    "--error-logfile", "-", \
    "--log-level", "info", \
    "--timeout", "120", \
    "--graceful-timeout", "30", \
    "--keep-alive", "5"]
