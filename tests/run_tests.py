# -*- coding: utf-8 -*-
"""
Test Runner Script for WebShield LLM Integration
Runs all test suites and generates a comprehensive report
"""

import os
import subprocess
import sys
from datetime import datetime

# Force UTF-8 encoding for Windows console
if sys.platform == "win32":
    import codecs

    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")


def print_header(text):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")


def run_test_suite(test_file, description):
    """Run a specific test suite"""
    print_header(description)

    cmd = [sys.executable, "-m", "pytest", test_file, "-v", "-s", "--tb=short", "--color=yes"]

    try:
        result = subprocess.run(cmd, capture_output=False, text=True)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running {test_file}: {e}")
        return False


def main():
    """Main test runner"""
    print_header(f"WebShield LLM Integration Test Suite - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if server is running
    print("Checking if server is running...")
    try:
        import httpx

        httpx.get("http://localhost:8000/", timeout=5.0)
        print("✅ Server is running\n")
    except Exception:
        print("⚠️  WARNING: Server may not be running at http://localhost:8000")
        print("   Some tests may fail. Start server with: python start_server.py\n")

    # Test suites to run
    test_suites = [
        ("tests/test_llm_service.py", "LLM Service Tests"),
        ("tests/test_scan_report_integration.py", "Scan Report Integration Tests"),
        ("tests/test_e2e_scan_report.py", "End-to-End Scan Report Tests"),
    ]

    results = {}

    for test_file, description in test_suites:
        if os.path.exists(test_file):
            success = run_test_suite(test_file, description)
            results[description] = success
        else:
            print(f"⚠️  Test file not found: {test_file}")
            results[description] = False

    # Print summary
    print_header("Test Summary")

    all_passed = True
    for description, success in results.items():
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{status} - {description}")
        if not success:
            all_passed = False

    print("\n" + "=" * 80)

    if all_passed:
        print("🎉 All tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed. Please review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
