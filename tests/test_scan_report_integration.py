# -*- coding: utf-8 -*-
"""
Test Suite for Scan Report Integration
Tests that scan results include LLM data and are structured correctly
"""

import codecs
import sys

# Force UTF-8 encoding for Windows console
if sys.platform == "win32":
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")

import asyncio
import contextlib
import json

import pytest

from backend.scan import _do_scan

pytestmark = pytest.mark.integration


class TestScanReportIntegration:
    """Test scan report data integration"""

    @pytest.mark.asyncio
    async def test_scan_includes_llm_analysis(self):
        """Test that scan results include LLM analysis"""
        # Perform a scan
        scan_id = "test-scan-" + str(asyncio.get_event_loop().time())
        url = "https://www.google.com"

        result = await _do_scan(url, scan_id)

        # Verify result structure
        assert result is not None
        assert hasattr(result, "results")

        scan_result = result.results
        assert scan_result is not None
        assert hasattr(scan_result, "detection_details")

        # Verify LLM analysis is present
        detection_details = scan_result.detection_details
        assert "llm_analysis" in detection_details

        llm_data = detection_details["llm_analysis"]

        # Check if LLM analysis was performed or marked unavailable
        if llm_data.get("status") != "unavailable":
            # LLM analysis was performed
            assert "llm_analysis" in llm_data or "overall_assessment" in llm_data
            print("✅ LLM analysis included in scan results")
        else:
            # LLM analysis unavailable (expected if no API key)
            assert "message" in llm_data
            print("ℹ️ LLM analysis unavailable (expected without API key)")

    @pytest.mark.asyncio
    async def test_scan_detection_details_structure(self):
        """Test that detection_details has all required components"""
        scan_id = "test-scan-details-" + str(asyncio.get_event_loop().time())
        url = "https://example.com"

        result = await _do_scan(url, scan_id)
        detection_details = result.results.detection_details

        # Verify all analysis components are present
        required_components = [
            "url_analysis",
            "ssl_analysis",
            "content_analysis",
            "virustotal_analysis",
            "ml_analysis",
            "llm_analysis",
            "database_health",
        ]

        for component in required_components:
            assert component in detection_details, f"Missing component: {component}"

        print("✅ All detection components present")
        print(f"   Components: {list(detection_details.keys())}")

    @pytest.mark.asyncio
    async def test_llm_analysis_data_types(self):
        """Test that LLM analysis data types are correct"""
        scan_id = "test-scan-types-" + str(asyncio.get_event_loop().time())
        url = "https://www.microsoft.com"

        result = await _do_scan(url, scan_id)
        llm_data = result.results.detection_details.get("llm_analysis", {})

        if llm_data.get("status") != "unavailable":
            # Verify data types
            if "llm_analysis" in llm_data:
                llm_analysis = llm_data["llm_analysis"]

                # Check URL classification
                if "url_classification" in llm_analysis:
                    url_class = llm_analysis["url_classification"]
                    assert isinstance(url_class.get("confidence", 0), (int, float))
                    assert isinstance(url_class.get("label", ""), str)

                # Check content classification
                if "content_classification" in llm_analysis:
                    content_class = llm_analysis["content_classification"]
                    assert isinstance(content_class.get("confidence", 0), (int, float))
                    assert isinstance(content_class.get("label", ""), str)

                # Check explanation
                if "explanation" in llm_analysis:
                    explanation = llm_analysis["explanation"]
                    assert isinstance(explanation.get("explanation", ""), str)
                    assert isinstance(explanation.get("threat_factors", []), list)
                    assert isinstance(explanation.get("safety_factors", []), list)
                    assert isinstance(explanation.get("recommended_action", ""), str)

            print("✅ LLM data types are correct")
        else:
            print("ℹ️ Skipping type check (LLM unavailable)")

    @pytest.mark.asyncio
    async def test_scan_result_serialization(self):
        """Test that scan results can be serialized to JSON"""
        scan_id = "test-scan-json-" + str(asyncio.get_event_loop().time())
        url = "https://www.github.com"

        result = await _do_scan(url, scan_id)

        # Convert to dict
        result_dict = {
            "scan_id": result.scan_id,
            "url": result.url,
            "status": result.status,
            "results": {
                "url": result.results.url,
                "is_malicious": result.results.is_malicious,
                "threat_level": result.results.threat_level,
                "malicious_count": result.results.malicious_count,
                "suspicious_count": result.results.suspicious_count,
                "total_engines": result.results.total_engines,
                "detection_details": result.results.detection_details,
                "ssl_valid": result.results.ssl_valid,
                "domain_reputation": result.results.domain_reputation,
            },
        }

        # Try to serialize to JSON
        try:
            json_str = json.dumps(result_dict, default=str)
            assert len(json_str) > 0

            # Try to deserialize
            parsed = json.loads(json_str)
            assert parsed["scan_id"] == scan_id
            assert parsed["url"] == url

            print("✅ Scan results can be serialized to JSON")
            print(f"   JSON length: {len(json_str)} characters")
        except Exception as e:
            pytest.fail(f"JSON serialization failed: {e}")

    @pytest.mark.asyncio
    async def test_threat_level_calculation_with_llm(self):
        """Test that threat level is calculated correctly with LLM input"""
        scan_id = "test-threat-level-" + str(asyncio.get_event_loop().time())

        # Test with a potentially suspicious URL
        url = "http://login-verify-account.tk"

        result = await _do_scan(url, scan_id)

        # Verify threat level is set
        assert result.results.threat_level in ["low", "medium", "high"]

        # Verify is_malicious is boolean
        assert isinstance(result.results.is_malicious, bool)

        print("✅ Threat level calculation:")
        print(f"   URL: {url}")
        print(f"   Threat Level: {result.results.threat_level}")
        print(f"   Is Malicious: {result.results.is_malicious}")

    @pytest.mark.asyncio
    async def test_ml_analysis_integration(self):
        """Test that ML analysis is properly integrated"""
        scan_id = "test-ml-analysis-" + str(asyncio.get_event_loop().time())
        url = "https://www.amazon.com"

        result = await _do_scan(url, scan_id)
        detection_details = result.results.detection_details

        # Verify ML analysis exists
        assert "ml_analysis" in detection_details
        ml_analysis = detection_details["ml_analysis"]

        # Verify ML analysis structure
        assert "ml_enabled" in ml_analysis
        assert "ml_models_used" in ml_analysis
        assert "ml_confidence" in ml_analysis
        assert "ml_analysis_summary" in ml_analysis

        # Verify data types
        assert isinstance(ml_analysis["ml_enabled"], bool)
        assert isinstance(ml_analysis["ml_models_used"], list)
        assert isinstance(ml_analysis["ml_confidence"], (int, float))
        assert isinstance(ml_analysis["ml_analysis_summary"], dict)

        print("✅ ML analysis integration:")
        print(f"   ML Enabled: {ml_analysis['ml_enabled']}")
        print(f"   Models Used: {ml_analysis['ml_models_used']}")
        print(f"   Confidence: {ml_analysis['ml_confidence']:.2%}")


class TestScanReportChartData:
    """Test that scan results provide correct data for charts"""

    @pytest.mark.asyncio
    async def test_threat_score_chart_data(self):
        """Test data for threat score breakdown chart"""
        scan_id = "test-chart-threat-" + str(asyncio.get_event_loop().time())
        url = "https://www.reddit.com"

        result = await _do_scan(url, scan_id)
        details = result.results.detection_details

        # Extract scores for chart
        url_score = details.get("url_analysis", {}).get("suspicious_score", 0)
        content_score = details.get("content_analysis", {}).get("phishing_score", 0)
        ssl_score = details.get("ssl_analysis", {}).get("threat_score", 0)
        vt_score = result.results.malicious_count * 10 + result.results.suspicious_count * 5

        # Verify scores are valid
        assert 0 <= url_score <= 100
        assert 0 <= content_score <= 100
        assert 0 <= ssl_score <= 100
        assert 0 <= vt_score <= 1000  # Can exceed 100 with many detections

        print("✅ Threat score chart data:")
        print(f"   URL Score: {url_score}")
        print(f"   Content Score: {content_score}")
        print(f"   SSL Score: {ssl_score}")
        print(f"   VT Score: {vt_score}")

    @pytest.mark.asyncio
    async def test_detection_chart_data(self):
        """Test data for detection distribution chart"""
        scan_id = "test-chart-detection-" + str(asyncio.get_event_loop().time())
        url = "https://www.wikipedia.org"

        result = await _do_scan(url, scan_id)

        malicious_count = result.results.malicious_count
        suspicious_count = result.results.suspicious_count
        total_engines = result.results.total_engines
        clean_count = max(0, total_engines - malicious_count - suspicious_count)

        # Verify counts are valid
        assert malicious_count >= 0
        assert suspicious_count >= 0
        assert total_engines >= 0
        assert clean_count >= 0

        # Verify sum doesn't exceed total
        assert (malicious_count + suspicious_count) <= total_engines

        print("✅ Detection chart data:")
        print(f"   Malicious: {malicious_count}")
        print(f"   Suspicious: {suspicious_count}")
        print(f"   Clean: {clean_count}")
        print(f"   Total Engines: {total_engines}")

    @pytest.mark.asyncio
    async def test_confidence_chart_data(self):
        """Test data for confidence radar chart"""
        scan_id = "test-chart-confidence-" + str(asyncio.get_event_loop().time())
        url = "https://www.stackoverflow.com"

        result = await _do_scan(url, scan_id)
        details = result.results.detection_details

        # Extract confidence values
        url_confidence = details.get("url_analysis", {}).get("ml_confidence", 0) * 100
        content_confidence = details.get("content_analysis", {}).get("ml_confidence", 0) * 100

        llm_data = details.get("llm_analysis", {})
        llm_url_conf = 0
        llm_content_conf = 0

        if llm_data.get("status") != "unavailable" and "llm_analysis" in llm_data:
            llm_analysis = llm_data["llm_analysis"]
            llm_url_conf = llm_analysis.get("url_classification", {}).get("confidence", 0) * 100
            llm_content_conf = llm_analysis.get("content_classification", {}).get("confidence", 0) * 100

        # Verify all confidence values are percentages (0-100)
        assert 0 <= url_confidence <= 100
        assert 0 <= content_confidence <= 100
        assert 0 <= llm_url_conf <= 100
        assert 0 <= llm_content_conf <= 100

        print("✅ Confidence chart data:")
        print(f"   URL ML Confidence: {url_confidence:.1f}%")
        print(f"   Content ML Confidence: {content_confidence:.1f}%")
        print(f"   LLM URL Confidence: {llm_url_conf:.1f}%")
        print(f"   LLM Content Confidence: {llm_content_conf:.1f}%")


class TestScanReportScoreBreakdown:
    @pytest.mark.asyncio
    async def test_ml_confidence_does_not_inflate_risk_score_when_benign(self, monkeypatch):
        import backend.scan as scan_module

        class FakeDetector:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def analyze_url_patterns(self, url: str):
                return {
                    "suspicious_score": 0,
                    "detected_issues": [],
                    "domain": "example.com",
                    "is_suspicious": False,
                    "ml_enabled": True,
                    "ml_confidence": 0.99,
                }

            async def analyze_ssl_certificate(self, url: str):
                return {"valid": True, "threat_score": 0}

            async def analyze_content(self, url: str, max_bytes: int = 1024):
                return {
                    "phishing_score": 0,
                    "is_suspicious": False,
                    "content_length": 10,
                    "ml_enabled": True,
                    "ml_confidence": 0.98,
                    "detected_indicators": [],
                    "html_text": "hello",
                }

            async def check_virustotal(self, url: str):
                return {
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "total_engines": 0,
                    "fallback_mode": True,
                }

        class FakeLLM:
            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def classify_url(self, url: str):
                return {"success": False, "fallback": True}

            async def classify_html_content(self, html_text: str, url: str = ""):
                return {"success": False, "fallback": True}

            async def generate_explanation(
                self, url: str, url_classification, content_classification, ssl_analysis, vt_analysis
            ):
                return {"success": False, "fallback": True}

        @contextlib.contextmanager
        def fake_db_conn(*args, **kwargs):
            yield None

        monkeypatch.setattr(scan_module, "WebShieldDetector", FakeDetector)
        monkeypatch.setattr(scan_module, "LLMService", FakeLLM)
        monkeypatch.setattr(scan_module, "get_db_connection_with_retry", fake_db_conn)

        scan_id = "test-score-breakdown-" + str(asyncio.get_event_loop().time())
        url = "https://example.com"
        result = await _do_scan(url, scan_id)

        details = result.results.detection_details
        sb = details.get("score_breakdown")
        assert isinstance(sb, dict)
        assert sb.get("ml") == 0
        assert sb.get("total_score") == 0


class TestScanReportExplanations:
    """Test that explanations are generated correctly"""

    @pytest.mark.asyncio
    async def test_explanation_exists(self):
        """Test that explanation is generated"""
        scan_id = "test-explanation-" + str(asyncio.get_event_loop().time())
        url = "https://www.youtube.com"

        result = await _do_scan(url, scan_id)
        llm_data = result.results.detection_details.get("llm_analysis", {})

        if llm_data.get("status") != "unavailable":
            assert "llm_analysis" in llm_data
            llm_analysis = llm_data["llm_analysis"]

            if "explanation" in llm_analysis:
                explanation = llm_analysis["explanation"]

                # Verify explanation has required fields
                assert "explanation" in explanation or "risk_summary" in explanation
                assert "recommended_action" in explanation

                print("✅ Explanation generated:")
                print(f"   {explanation.get('explanation', 'N/A')[:100]}...")
        else:
            print("ℹ️ Skipping explanation test (LLM unavailable)")

    @pytest.mark.asyncio
    async def test_risk_factors_format(self):
        """Test that risk factors are properly formatted"""
        scan_id = "test-risk-factors-" + str(asyncio.get_event_loop().time())
        url = "http://suspicious-login.tk"

        result = await _do_scan(url, scan_id)
        llm_data = result.results.detection_details.get("llm_analysis", {})

        if llm_data.get("status") != "unavailable" and "llm_analysis" in llm_data:
            explanation = llm_data["llm_analysis"].get("explanation", {})

            # Verify threat_factors is a list
            if "threat_factors" in explanation:
                assert isinstance(explanation["threat_factors"], list)

                # Each factor should be a string
                for factor in explanation["threat_factors"]:
                    assert isinstance(factor, str)
                    assert len(factor) > 0

                print("✅ Risk factors properly formatted:")
                for i, factor in enumerate(explanation["threat_factors"][:3], 1):
                    print(f"   {i}. {factor}")

            # Verify safety_factors is a list
            if "safety_factors" in explanation:
                assert isinstance(explanation["safety_factors"], list)

                for factor in explanation["safety_factors"]:
                    assert isinstance(factor, str)
                    assert len(factor) > 0

                print("✅ Safety factors properly formatted")
        else:
            print("ℹ️ Skipping risk factors test (LLM unavailable)")


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
