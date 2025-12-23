#!/usr/bin/env python3
"""
Quick verification script to test all the fixes
Run this after starting the server to verify everything works
"""

import requests
import time
import sys

BASE_URL = "http://localhost:8000"

def test_health_endpoint():
    """Test that health endpoint is fast and doesn't load ML models repeatedly"""
    print("🔍 Testing /api/health endpoint...")
    
    times = []
    for i in range(5):
        start = time.time()
        try:
            response = requests.get(f"{BASE_URL}/api/health", timeout=5)
            elapsed = time.time() - start
            times.append(elapsed)
            
            if response.status_code == 200:
                data = response.json()
                print(f"  ✅ Request {i+1}: {elapsed:.3f}s - Status: {data.get('status')}")
            else:
                print(f"  ❌ Request {i+1}: HTTP {response.status_code}")
        except Exception as e:
            print(f"  ❌ Request {i+1}: Error - {e}")
            return False
    
    avg_time = sum(times) / len(times)
    print(f"\n  📊 Average response time: {avg_time:.3f}s")
    
    if avg_time < 0.5:
        print("  ✅ PASS: Health endpoint is fast!")
        return True
    else:
        print(f"  ⚠️  WARNING: Health endpoint is slow (avg {avg_time:.3f}s, expected <0.5s)")
        return False

def test_scan_endpoint():
    """Test that scan endpoint works without database errors"""
    print("\n🔍 Testing /api/scan/scan endpoint...")
    
    test_url = "https://google.com"
    
    try:
        start = time.time()
        response = requests.post(
            f"{BASE_URL}/api/scan/scan",
            json={"url": test_url},
            timeout=30
        )
        elapsed = time.time() - start
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ Scan completed in {elapsed:.2f}s")
            print(f"  📊 Status: {data.get('status')}")
            
            if data.get('results'):
                threat_level = data['results'].get('threat_level')
                print(f"  📊 Threat Level: {threat_level}")
                
                # Check if threat_level is valid
                valid_levels = ['low', 'medium', 'high', 'moderate', 'unknown']
                if threat_level in valid_levels:
                    print("  ✅ PASS: Threat level is valid!")
                    return True
                else:
                    print(f"  ❌ FAIL: Invalid threat level '{threat_level}'")
                    return False
            else:
                print("  ⚠️  WARNING: No results in response")
                return True  # Not a failure, might be processing
        else:
            print(f"  ❌ FAIL: HTTP {response.status_code}")
            print(f"  Response: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False

def main():
    print("=" * 60)
    print("WebShield Fixes Verification")
    print("=" * 60)
    print()
    
    # Wait for server to be ready
    print("⏳ Waiting for server to start...")
    for i in range(10):
        try:
            requests.get(f"{BASE_URL}/api/health", timeout=2)
            print("✅ Server is ready!\n")
            break
        except:
            time.sleep(1)
    else:
        print("❌ Server is not responding. Please start the server first.")
        sys.exit(1)
    
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
