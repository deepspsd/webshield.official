"""
Quick Validation Script for WebShield LLM Integration
Tests all features without requiring pytest or complex setup
Run from project root: python tests/quick_validation.py
"""

import asyncio
import os
import sys

# Fix encoding for Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import httpx

    from backend.llm_service import LLMService
    from backend.scan import _do_scan
except ImportError as e:
    print(f"[ERROR] Import error: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)


def print_test(name, passed, details=""):
    """Print test result"""
    status = "[PASS]" if passed else "[FAIL]"
    print(f"{status} - {name}")
    if details:
        print(f"         {details}")


async def test_llm_service_basic():
    """Test 1: LLM Service Initialization"""
    print_header("Test 1: LLM Service Initialization")

    try:
        async with LLMService() as llm:
            has_api_key = llm.api_key is not None and len(llm.api_key) > 0
            print_test("LLM Service Created", True)
            print_test("API Key Configured", has_api_key, "Set GROQ_API_KEY in .env" if not has_api_key else "")
            return True
    except Exception as e:
        print_test("LLM Service Creation", False, str(e))
        return False


async def test_url_classification():
    """Test 2: URL Classification"""
    print_header("Test 2: URL Classification")

    try:
        async with LLMService() as llm:
            # Test with safe URL
            result = await llm.classify_url("https://www.google.com")

            has_confidence = "confidence" in result
            has_label = "label" in result
            has_model = "model" in result
            valid_confidence = 0 <= result.get("confidence", -1) <= 1

            print_test("URL Classification Returns Data", has_confidence and has_label)
            print_test("Confidence Value Valid", valid_confidence, f"Confidence: {result.get('confidence', 'N/A')}")
            print_test("Label Present", has_label, f"Label: {result.get('label', 'N/A')}")
            print_test("Model Info Present", has_model, f"Model: {result.get('model', 'N/A')}")

            if result.get("fallback"):
                print("         [INFO] Using fallback (LLM unavailable)")

            return has_confidence and has_label and valid_confidence
    except Exception as e:
        print_test("URL Classification", False, str(e))
        return False


async def test_content_classification():
    """Test 3: Content Classification"""
    print_header("Test 3: Content Classification")

    try:
        async with LLMService() as llm:
            html = "<html><body><h1>Welcome</h1><p>This is a test page.</p></body></html>"
            result = await llm.classify_html_content(html)

            has_confidence = "confidence" in result
            has_label = "label" in result
            valid_confidence = 0 <= result.get("confidence", -1) <= 1

            print_test("Content Classification Returns Data", has_confidence and has_label)
            print_test("Confidence Value Valid", valid_confidence, f"Confidence: {result.get('confidence', 'N/A')}")
            print_test("Label Present", has_label, f"Label: {result.get('label', 'N/A')}")

            if result.get("fallback"):
                print("         [INFO] Using fallback (LLM unavailable)")

            return has_confidence and has_label and valid_confidence
    except Exception as e:
        print_test("Content Classification", False, str(e))
        return False


async def test_explanation_generation():
    """Test 4: Explanation Generation"""
    print_header("Test 4: Explanation Generation")

    try:
        async with LLMService() as llm:
            url_class = {"is_malicious": False, "confidence": 0.9, "label": "benign"}
            content_class = {"is_phishing": False, "confidence": 0.85, "label": "legitimate"}
            ssl = {"valid": True}
            vt = {"malicious_count": 0, "suspicious_count": 0, "total_engines": 70}

            result = await llm.generate_explanation("https://www.google.com", url_class, content_class, ssl, vt)

            has_explanation = "explanation" in result or "risk_summary" in result
            has_action = "recommended_action" in result
            has_factors = "threat_factors" in result

            print_test("Explanation Generated", has_explanation)
            print_test(
                "Recommended Action Present", has_action, f"Action: {result.get('recommended_action', 'N/A')[:50]}..."
            )
            print_test("Risk Factors Present", has_factors)

            if result.get("fallback"):
                print("         [INFO] Using fallback (LLM unavailable)")

            return has_explanation and has_action
    except Exception as e:
        print_test("Explanation Generation", False, str(e))
        return False


async def test_complete_llm_analysis():
    """Test 5: Complete LLM Analysis Pipeline"""
    print_header("Test 5: Complete LLM Analysis Pipeline")

    try:
        async with LLMService() as llm:
            result = await llm.analyze_with_llm(
                url="https://www.github.com",
                html_content="<html><body>GitHub</body></html>",
                ssl_analysis={"valid": True},
                vt_analysis={"malicious_count": 0, "total_engines": 70},
            )

            has_llm_analysis = "llm_analysis" in result
            has_assessment = "overall_assessment" in result
            has_models = "models_used" in result

            print_test("LLM Analysis Present", has_llm_analysis)
            print_test("Overall Assessment Present", has_assessment)
            print_test("Models Used Info Present", has_models)

            if has_llm_analysis:
                llm_data = result["llm_analysis"]
                has_url_class = "url_classification" in llm_data
                has_content_class = "content_classification" in llm_data
                has_explanation = "explanation" in llm_data

                print_test("  URL Classification", has_url_class)
                print_test("  Content Classification", has_content_class)
                print_test("  Explanation", has_explanation)

            if has_assessment:
                assessment = result["overall_assessment"]
                print(f"         Is Malicious: {assessment.get('is_malicious', 'N/A')}")
                print(f"         Confidence: {assessment.get('confidence', 0):.2%}")

            return has_llm_analysis and has_assessment
    except Exception as e:
        print_test("Complete LLM Analysis", False, str(e))
        return False


async def test_scan_integration():
    """Test 6: Scan Integration with LLM"""
    print_header("Test 6: Scan Integration with LLM")

    try:
        scan_id = f"test-{asyncio.get_event_loop().time()}"
        result = await _do_scan("https://www.microsoft.com", scan_id)

        has_results = result.results is not None
        has_detection_details = hasattr(result.results, "detection_details") if has_results else False

        print_test("Scan Completed", has_results)
        print_test("Detection Details Present", has_detection_details)

        if has_detection_details:
            details = result.results.detection_details
            has_llm = "llm_analysis" in details
            has_ml = "ml_analysis" in details
            has_url = "url_analysis" in details
            has_ssl = "ssl_analysis" in details
            has_content = "content_analysis" in details
            has_vt = "virustotal_analysis" in details

            print_test("  LLM Analysis in Results", has_llm)
            print_test("  ML Analysis in Results", has_ml)
            print_test("  URL Analysis in Results", has_url)
            print_test("  SSL Analysis in Results", has_ssl)
            print_test("  Content Analysis in Results", has_content)
            print_test("  VirusTotal Analysis in Results", has_vt)

            if has_llm:
                llm_data = details["llm_analysis"]
                if llm_data.get("status") == "unavailable":
                    print("         [INFO] LLM analysis unavailable (expected without API key)")
                else:
                    print("         [OK] LLM analysis data included")

            return has_llm and has_ml

        return has_results
    except Exception as e:
        print_test("Scan Integration", False, str(e))
        return False


async def test_api_endpoint():
    """Test 7: API Endpoint"""
    print_header("Test 7: API Endpoint Integration")

    try:
        async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=30.0) as client:
            # Test scan endpoint
            response = await client.post(
                "/api/scan/scan", json={"url": "https://www.wikipedia.org", "user_email": "test@example.com"}
            )

            api_works = response.status_code == 200
            print_test("API Endpoint Accessible", api_works)

            if api_works:
                data = response.json()
                has_scan_id = "scan_id" in data
                has_status = "status" in data

                print_test("  Scan ID Returned", has_scan_id)
                print_test("  Status Returned", has_status)

                if has_scan_id:
                    scan_id = data["scan_id"]
                    print(f"         Scan ID: {scan_id}")

                    # Wait a bit for scan to process
                    await asyncio.sleep(5)

                    # Get results
                    result_response = await client.get(f"/api/scan/scan/{scan_id}")
                    result_data = result_response.json()

                    if result_data.get("status") == "completed":
                        has_results = "results" in result_data
                        print_test("  Scan Completed", has_results)

                        if has_results:
                            results = result_data["results"]
                            has_detection_details = "detection_details" in results
                            print_test("  Detection Details in API Response", has_detection_details)

                            if has_detection_details:
                                has_llm_in_api = "llm_analysis" in results["detection_details"]
                                print_test("  LLM Analysis in API Response", has_llm_in_api)
                                return has_llm_in_api
                    else:
                        print(f"         Status: {result_data.get('status', 'unknown')}")

                return has_scan_id and has_status

            return False
    except httpx.ConnectError:
        print_test("API Endpoint", False, "Server not running at http://localhost:8000")
        print("         Start server with: python start_server.py")
        return False
    except Exception as e:
        print_test("API Endpoint", False, str(e))
        return False


async def test_chart_data_structure():
    """Test 8: Chart Data Structure"""
    print_header("Test 8: Chart Data Structure")

    try:
        scan_id = f"test-chart-{asyncio.get_event_loop().time()}"
        result = await _do_scan("https://www.amazon.com", scan_id)

        details = result.results.detection_details

        # Extract data for charts
        url_score = details.get("url_analysis", {}).get("suspicious_score", 0)
        content_score = details.get("content_analysis", {}).get("phishing_score", 0)
        ssl_score = details.get("ssl_analysis", {}).get("threat_score", 0)

        malicious_count = result.results.malicious_count
        suspicious_count = result.results.suspicious_count
        total_engines = result.results.total_engines

        # Validate chart data
        valid_url_score = 0 <= url_score <= 100
        valid_content_score = 0 <= content_score <= 100
        valid_ssl_score = 0 <= ssl_score <= 100
        valid_counts = malicious_count >= 0 and suspicious_count >= 0 and total_engines >= 0

        print_test("URL Score Valid", valid_url_score, f"Score: {url_score}")
        print_test("Content Score Valid", valid_content_score, f"Score: {content_score}")
        print_test("SSL Score Valid", valid_ssl_score, f"Score: {ssl_score}")
        print_test(
            "Detection Counts Valid",
            valid_counts,
            f"Malicious: {malicious_count}, Suspicious: {suspicious_count}, Total: {total_engines}",
        )

        # Check ML confidence data
        url_conf = details.get("url_analysis", {}).get("ml_confidence", 0)
        content_conf = details.get("content_analysis", {}).get("ml_confidence", 0)

        valid_confidences = 0 <= url_conf <= 1 and 0 <= content_conf <= 1
        print_test("ML Confidence Values Valid", valid_confidences, f"URL: {url_conf:.2%}, Content: {content_conf:.2%}")

        return valid_url_score and valid_content_score and valid_counts
    except Exception as e:
        print_test("Chart Data Structure", False, str(e))
        return False


async def main():
    """Run all tests"""
    print_header("WebShield LLM Integration - Quick Validation")
    print("Testing all features of the scan report integration...")

    tests = [
        ("LLM Service Basic", test_llm_service_basic),
        ("URL Classification", test_url_classification),
        ("Content Classification", test_content_classification),
        ("Explanation Generation", test_explanation_generation),
        ("Complete LLM Analysis", test_complete_llm_analysis),
        ("Scan Integration", test_scan_integration),
        ("API Endpoint", test_api_endpoint),
        ("Chart Data Structure", test_chart_data_structure),
    ]

    results = {}

    for name, test_func in tests:
        try:
            result = await test_func()
            results[name] = result
        except Exception as e:
            print(f"\n[ERROR] Test '{name}' crashed: {e}")
            results[name] = False

    # Summary
    print_header("Test Summary")

    passed = sum(1 for r in results.values() if r)
    total = len(results)

    for name, result in results.items():
        status = "[PASSED]" if result else "[FAILED]"
        print(f"{status} - {name}")

    print(f"\n{'=' * 80}")
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    print(f"{'=' * 80}\n")

    if passed == total:
        print("[SUCCESS] All tests passed! LLM integration is working correctly.")
        print("\nNext steps:")
        print("1. Open http://localhost:8000/scan-url.html")
        print("2. Scan a URL")
        print("3. View the scan report with charts and LLM analysis")
    else:
        print("[WARNING] Some tests failed. Common issues:")
        print("1. GROQ_API_KEY not set in .env (LLM will use fallback)")
        print("2. Server not running (start with: python start_server.py)")
        print("3. Dependencies not installed (run: pip install -r requirements.txt)")

    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[FATAL ERROR] {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
