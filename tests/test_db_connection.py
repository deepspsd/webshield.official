#!/usr/bin/env python3
"""Test database connection"""
import os
import sys
from pathlib import Path

import pytest
from dotenv import load_dotenv

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

load_dotenv()

# This file is primarily a manual DB connectivity diagnostic. It should not run in CI by default.
_run_db_test = os.getenv("RUN_DB_TEST", "false").lower() in ("1", "true", "yes")
if not _run_db_test:
    pytest.skip("Skipping DB connectivity diagnostic (set RUN_DB_TEST=true to enable)", allow_module_level=True)

print("=" * 60)
print("DATABASE CONNECTION TEST")
print("=" * 60)

# Check environment variables
print("\n1. Environment Variables:")
print(f"   DB_URL: {os.getenv('DB_URL')}")
print(f"   DB_HOST: {os.getenv('DB_HOST')}")
print(f"   DB_PORT: {os.getenv('DB_PORT')}")
print(f"   DB_USER: {os.getenv('DB_USER')}")
print(f"   DB_PASSWORD: {'*' * len(os.getenv('DB_PASSWORD', ''))}")
print(f"   DB_NAME: {os.getenv('DB_NAME')}")
print(f"   DB_SSL_MODE: {os.getenv('DB_SSL_MODE')}")
print(f"   DB_SSL_CA: {os.getenv('DB_SSL_CA')}")

# Check SSL certificate
ssl_ca_path = os.getenv("DB_SSL_CA")
if ssl_ca_path:
    print("\n2. SSL Certificate Check:")
    print(f"   Path: {ssl_ca_path}")
    print(f"   Exists: {os.path.exists(ssl_ca_path)}")
    if not os.path.exists(ssl_ca_path):
        print("   ❌ ERROR: SSL certificate file not found!")
else:
    print("\n2. SSL Certificate: Not configured")

# Test connection
print("\n3. Testing Database Connection:")
try:
    from backend.db import get_mysql_connection

    print("   Attempting to connect...")
    conn = get_mysql_connection()

    if conn and conn.is_connected():
        print("   ✅ Connection successful!")

        # Get server info
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()
        print(f"   MySQL Version: {version[0]}")

        cursor.execute("SELECT DATABASE()")
        db = cursor.fetchone()
        print(f"   Current Database: {db[0]}")

        cursor.close()
        conn.close()
        print("   Connection closed successfully")
    else:
        print("   ❌ Connection failed - returned None or not connected")

except Exception as e:
    print(f"   ❌ Connection error: {e}")
    import traceback

    print("\n   Full traceback:")
    print(traceback.format_exc())

print("\n" + "=" * 60)
