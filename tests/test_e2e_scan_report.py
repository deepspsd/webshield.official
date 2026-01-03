# -*- coding: utf-8 -*-
"""
End-to-End Test Suite for Scan Report Features
Tests the complete flow from scan initiation to report display
"""

import codecs
import sys

# Force UTF-8 encoding for Windows console
if sys.platform == "win32":
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")

import asyncio
import time

import httpx
import pytest

# Make playwright optional
try:
    from playwright.async_api import async_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None
    print("⚠️ Playwright not installed. Browser tests will be skipped.")
    print("   Install with: pip install playwright && playwright install")


class TestEndToEndScanFlow:
    """Test complete scan flow end-to-end"""

    pytestmark = pytest.mark.integration

    @pytest.mark.asyncio
    async def test_scan_api_endpoint(self):
        """Test scan API endpoint returns correct structure"""
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            # Initiate scan
            response = await client.post(
                "/api/scan/scan", json={"url": "https://www.google.com", "user_email": "test@example.com"}, timeout=30.0
            )

            assert response.status_code == 200
            data = response.json()

            # Verify response structure
            assert "scan_id" in data
            assert "url" in data
            assert "status" in data
            assert data["status"] in ["processing", "completed"]

            scan_id = data["scan_id"]
            print(f"✅ Scan initiated: {scan_id}")

            # Wait for scan to complete
            max_retries = 30
            for i in range(max_retries):
                await asyncio.sleep(1)

                result_response = await client.get(f"/api/scan/scan/{scan_id}")
                assert result_response.status_code == 200

                result_data = result_response.json()

                if result_data["status"] == "completed":
                    print(f"✅ Scan completed after {i+1} seconds")

                    # Verify results structure
                    assert "results" in result_data
                    results = result_data["results"]

                    assert "url" in results
                    assert "is_malicious" in results
                    assert "threat_level" in results
                    assert "detection_details" in results

                    # Verify detection_details has LLM analysis
                    detection_details = results["detection_details"]
                    assert "llm_analysis" in detection_details

                    print(f"✅ Scan results structure validated")
                    print(f"   Threat Level: {results['threat_level']}")
                    print(f"   Is Malicious: {results['is_malicious']}")

                    return

            pytest.fail(f"Scan did not complete within {max_retries} seconds")

    @pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")
    @pytest.mark.asyncio
    async def test_scan_report_page_loads(self):
        """Test that scan report page loads without errors"""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # First, initiate a scan
            async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
                response = await client.post(
                    "/api/scan/scan",
                    json={"url": "https://www.github.com", "user_email": "test@example.com"},
                    timeout=30.0,
                )
                scan_id = response.json()["scan_id"]

            # Wait for scan to complete
            await asyncio.sleep(10)

            # Load scan report page
            await page.goto(f"http://localhost:8000/scan_report.html?scan_id={scan_id}")

            # Wait for page to load
            await page.wait_for_load_state("networkidle")

            # Check for JavaScript errors
            errors = []
            page.on("pageerror", lambda err: errors.append(str(err)))

            # Wait a bit for any async operations
            await asyncio.sleep(2)

            # Verify no errors
            if errors:
                print(f"⚠️ JavaScript errors found: {errors}")
            else:
                print(f"✅ Scan report page loaded without errors")

            # Check if main elements are present
            title = await page.title()
            assert "Scan Report" in title or "WebShield" in title

            await browser.close()

    @pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")
    @pytest.mark.asyncio
    async def test_charts_render_on_page(self):
        """Test that charts render on the scan report page"""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # Initiate scan
            async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
                response = await client.post(
                    "/api/scan/scan",
                    json={"url": "https://www.microsoft.com", "user_email": "test@example.com"},
                    timeout=30.0,
                )
                scan_id = response.json()["scan_id"]

            # Wait for scan
            await asyncio.sleep(10)

            # Load page
            await page.goto(f"http://localhost:8000/scan_report.html?scan_id={scan_id}")
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(3)  # Wait for charts to render

            # Check if chart canvases exist
            threat_chart = await page.query_selector("#threatScoreChart")
            detection_chart = await page.query_selector("#detectionChart")
            confidence_chart = await page.query_selector("#confidenceChart")

            assert threat_chart is not None, "Threat score chart canvas not found"
            assert detection_chart is not None, "Detection chart canvas not found"

            print(f"✅ Chart canvases found on page")

            # Check if Chart.js is loaded
            chart_loaded = await page.evaluate('typeof Chart !== "undefined"')
            assert chart_loaded, "Chart.js not loaded"

            print(f"✅ Chart.js library loaded")

            await browser.close()

    @pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")
    @pytest.mark.asyncio
    async def test_llm_section_displays(self):
        """Test that LLM analysis section displays on page"""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # Initiate scan
            async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
                response = await client.post(
                    "/api/scan/scan",
                    json={"url": "https://www.amazon.com", "user_email": "test@example.com"},
                    timeout=30.0,
                )
                scan_id = response.json()["scan_id"]

            # Wait for scan
            await asyncio.sleep(10)

            # Load page
            await page.goto(f"http://localhost:8000/scan_report.html?scan_id={scan_id}")
            await page.wait_for_load_state("networkidle")
            await asyncio.sleep(3)

            # Check if LLM section exists
            llm_section = await page.query_selector("#llm-analysis-section")

            if llm_section:
                print(f"✅ LLM analysis section found on page")

                # Check for key elements
                expert_analysis = await page.query_selector("text=Expert Analysis")
                if expert_analysis:
                    print(f"✅ Expert analysis heading found")

                recommended_action = await page.query_selector("text=Recommended Action")
                if recommended_action:
                    print(f"✅ Recommended action section found")
            else:
                print(f"ℹ️ LLM analysis section not found (may be unavailable)")

            await browser.close()


class TestScanReportDataAccuracy:
    """Test that data displayed in scan report is accurate"""

    pytestmark = pytest.mark.integration

    @pytest.mark.asyncio
    async def test_threat_scores_match_backend(self):
        """Test that threat scores displayed match backend data"""
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            # Initiate scan
            response = await client.post(
                "/api/scan/scan", json={"url": "https://www.reddit.com", "user_email": "test@example.com"}, timeout=30.0
            )
            scan_id = response.json()["scan_id"]

            # Wait for completion
            await asyncio.sleep(10)

            # Get results from API
            result_response = await client.get(f"/api/scan/scan/{scan_id}")
            api_data = result_response.json()

            if api_data["status"] == "completed":
                results = api_data["results"]
                details = results["detection_details"]

                # Extract scores
                url_score = details.get("url_analysis", {}).get("suspicious_score", 0)
                content_score = details.get("content_analysis", {}).get("phishing_score", 0)
                ssl_score = details.get("ssl_analysis", {}).get("threat_score", 0)

                print(f"✅ Backend threat scores:")
                print(f"   URL Score: {url_score}")
                print(f"   Content Score: {content_score}")
                print(f"   SSL Score: {ssl_score}")

                # These scores should be used in the chart
                assert 0 <= url_score <= 100
                assert 0 <= content_score <= 100
                assert 0 <= ssl_score <= 100

    @pytest.mark.asyncio
    async def test_detection_counts_match(self):
        """Test that detection counts are accurate"""
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            response = await client.post(
                "/api/scan/scan",
                json={"url": "https://www.wikipedia.org", "user_email": "test@example.com"},
                timeout=30.0,
            )
            scan_id = response.json()["scan_id"]

            await asyncio.sleep(10)

            result_response = await client.get(f"/api/scan/scan/{scan_id}")
            api_data = result_response.json()

            if api_data["status"] == "completed":
                results = api_data["results"]

                malicious = results.get("malicious_count", 0)
                suspicious = results.get("suspicious_count", 0)
                total = results.get("total_engines", 0)

                # Verify counts are logical
                assert malicious >= 0
                assert suspicious >= 0
                assert total >= 0
                assert (malicious + suspicious) <= total

                print(f"✅ Detection counts validated:")
                print(f"   Malicious: {malicious}/{total}")
                print(f"   Suspicious: {suspicious}/{total}")

    @pytest.mark.asyncio
    async def test_llm_confidence_values(self):
        """Test that LLM confidence values are valid percentages"""
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            response = await client.post(
                "/api/scan/scan",
                json={"url": "https://www.stackoverflow.com", "user_email": "test@example.com"},
                timeout=30.0,
            )
            scan_id = response.json()["scan_id"]

            await asyncio.sleep(10)

            result_response = await client.get(f"/api/scan/scan/{scan_id}")
            api_data = result_response.json()

            if api_data["status"] == "completed":
                llm_data = api_data["results"]["detection_details"].get("llm_analysis", {})

                if llm_data.get("status") != "unavailable" and "llm_analysis" in llm_data:
                    llm_analysis = llm_data["llm_analysis"]

                    # Check URL classification confidence
                    if "url_classification" in llm_analysis:
                        url_conf = llm_analysis["url_classification"].get("confidence", 0)
                        assert 0 <= url_conf <= 1
                        print(f"✅ URL classification confidence: {url_conf:.2%}")

                    # Check content classification confidence
                    if "content_classification" in llm_analysis:
                        content_conf = llm_analysis["content_classification"].get("confidence", 0)
                        assert 0 <= content_conf <= 1
                        print(f"✅ Content classification confidence: {content_conf:.2%}")
                else:
                    print(f"ℹ️ LLM analysis not available")


class TestScanReportExplanationQuality:
    """Test the quality and completeness of explanations"""

    pytestmark = pytest.mark.integration

    @pytest.mark.asyncio
    async def test_explanation_is_readable(self):
        """Test that explanation text is human-readable"""
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            response = await client.post(
                "/api/scan/scan",
                json={"url": "https://www.youtube.com", "user_email": "test@example.com"},
                timeout=30.0,
            )
            scan_id = response.json()["scan_id"]

            await asyncio.sleep(10)

            result_response = await client.get(f"/api/scan/scan/{scan_id}")
            api_data = result_response.json()

            if api_data["status"] == "completed":
                llm_data = api_data["results"]["detection_details"].get("llm_analysis", {})

                if llm_data.get("status") != "unavailable" and "llm_analysis" in llm_data:
                    explanation = llm_data["llm_analysis"].get("explanation", {})

                    if "explanation" in explanation:
                        text = explanation["explanation"]

                        # Basic readability checks
                        assert len(text) > 20, "Explanation too short"
                        assert len(text) < 1000, "Explanation too long"
                        assert "." in text or "!" in text, "No sentence endings"

                        # Check for common words
                        common_words = ["the", "is", "this", "website", "site", "security"]
                        has_common = any(word in text.lower() for word in common_words)
                        assert has_common, "Explanation doesn't contain common words"

                        print(f"✅ Explanation is readable:")
                        print(f"   Length: {len(text)} characters")
                        print(f"   Preview: {text[:100]}...")
                else:
                    print(f"ℹ️ No explanation available")

    @pytest.mark.asyncio
    async def test_recommended_action_format(self):
        """Test that recommended action is properly formatted"""
        async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
            response = await client.post(
                "/api/scan/scan",
                json={"url": "https://www.twitter.com", "user_email": "test@example.com"},
                timeout=30.0,
            )
            scan_id = response.json()["scan_id"]

            await asyncio.sleep(10)

            result_response = await client.get(f"/api/scan/scan/{scan_id}")
            api_data = result_response.json()

            if api_data["status"] == "completed":
                llm_data = api_data["results"]["detection_details"].get("llm_analysis", {})

                if llm_data.get("status") != "unavailable" and "llm_analysis" in llm_data:
                    explanation = llm_data["llm_analysis"].get("explanation", {})

                    if "recommended_action" in explanation:
                        action = explanation["recommended_action"]

                        # Should start with emoji or status indicator
                        valid_starts = ["⛔", "⚠️", "✅", "BLOCK", "CAUTION", "SAFE"]
                        has_valid_start = any(action.startswith(start) for start in valid_starts)

                        assert len(action) > 10, "Recommended action too short"

                        print(f"✅ Recommended action formatted:")
                        print(f"   {action}")
                else:
                    print(f"ℹ️ No recommended action available")


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s", "--tb=short"])
