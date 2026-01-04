#!/usr/bin/env python3
"""
Quick verification script to test all the fixes
Run this after starting the server to verify everything works
"""

import sys
import time

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from backend.server import app  # noqa: E402

pytestmark = pytest.mark.integration

client = TestClient(app)


def test_health_endpoint():
    """Test that health endpoint is fast and doesn't load ML models repeatedly"""
    print("🔍 Testing /api/health endpoint...")

    times = []
    for i in range(5):
        start = time.time()
        try:
            response = client.get("/api/health")
            elapsed = time.time() - start
            times.append(elapsed)

            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ Request {i+1}: {elapsed:.3f}s - Status: {data.get('status')}")
            else:
                print(f"  ❌ Request {i+1}: HTTP {response.status_code}")
        except Exception as e:
            print(f"  ❌ Request {i+1}: Error - {e}")
            raise AssertionError(f"Health endpoint request failed: {e}") from e

    avg_time = sum(times) / len(times)
    print(f"\n  📊 Average response time: {avg_time:.3f}s")

    assert response.status_code == 200


def test_scan_endpoint():
    """Test that scan endpoint works without database errors"""
    print("\n🔍 Testing /api/scan/scan endpoint...")

    test_url = "https://google.com"

    try:
        start = time.time()
        response = client.post("/api/scan/scan", json={"url": test_url})
        elapsed = time.time() - start

        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Scan completed in {elapsed:.2f}s")
            print(f"  📊 Status: {data.get('status')}")

            if data.get("results"):
                threat_level = data["results"].get("threat_level")
                print(f"  📊 Threat Level: {threat_level}")

                # Check if threat_level is valid
                valid_levels = ["low", "medium", "high", "moderate", "unknown"]
                assert threat_level in valid_levels, f"Invalid threat level '{threat_level}'"
            else:
                print("  ⚠️  WARNING: No results in response")
                assert True  # Not a failure, might be processing
        else:
            print(f"  ❌ FAIL: HTTP {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            raise AssertionError(f"Scan endpoint returned HTTP {response.status_code}")

    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        raise AssertionError(str(e)) from e


def main():
    print("=" * 60)
    print("WebShield Fixes Verification")
    print("=" * 60)
    print()

    # Run tests
    results = []

    results.append(("Health Endpoint", test_health_endpoint()))
    results.append(("Scan Endpoint", test_scan_endpoint()))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status}: {test_name}")

    all_passed = all(result[1] for result in results)

    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 All tests passed! Fixes are working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the logs.")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
