# -*- coding: utf-8 -*-
"""
Test Suite for LLM Service Integration
Tests URL classification, content analysis, and explanation generation
"""

import codecs
import sys

# Force UTF-8 encoding for Windows console
if sys.platform == "win32":
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "strict")
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "strict")


import pytest

from backend.llm_service import LLMService


class TestLLMService:
    """Test LLM Service functionality"""

    @pytest.mark.asyncio
    async def test_llm_service_initialization(self):
        """Test LLM service can be initialized"""
        async with LLMService() as llm:
            assert llm is not None
            assert llm.api_key is not None or llm.api_key == ""  # May be empty if not configured

    @pytest.mark.asyncio
    async def test_url_classification_malicious(self):
        """Test URL classification with suspicious URL"""
        async with LLMService() as llm:
            result = await llm.classify_url("http://phishing-login-verify.tk/secure/account")

            # Verify result structure
            assert "success" in result or "is_malicious" in result
            assert "confidence" in result
            assert "label" in result
            assert "model" in result

            # Check confidence is valid
            assert 0 <= result["confidence"] <= 1

            print(f"✅ URL Classification Result: {result}")

    @pytest.mark.asyncio
    async def test_url_classification_safe(self):
        """Test URL classification with safe URL"""
        async with LLMService() as llm:
            result = await llm.classify_url("https://www.google.com")

            assert "confidence" in result
            assert "label" in result
            assert 0 <= result["confidence"] <= 1

            print(f"✅ Safe URL Classification: {result}")

    @pytest.mark.asyncio
    async def test_content_classification_phishing(self):
        """Test content classification with phishing content"""
        phishing_html = """
        <html>
        <body>
            <h1>Urgent: Verify Your Account</h1>
            <p>Your account has been suspended. Click here immediately to verify your identity.</p>
            <form action="http://fake-bank.com/login">
                <input type="password" name="password" placeholder="Enter your password">
                <button>Verify Now</button>
            </form>
        </body>
        </html>
        """

        async with LLMService() as llm:
            result = await llm.classify_html_content(phishing_html)

            # Verify result structure
            assert "confidence" in result
            assert "label" in result
            assert "is_phishing" in result or "success" in result
            assert 0 <= result["confidence"] <= 1

            print(f"✅ Phishing Content Classification: {result}")

    @pytest.mark.asyncio
    async def test_content_classification_legitimate(self):
        """Test content classification with legitimate content"""
        legitimate_html = """
        <html>
        <body>
            <h1>Welcome to Our Website</h1>
            <p>Learn about our products and services.</p>
            <nav>
                <a href="/about">About Us</a>
                <a href="/contact">Contact</a>
            </nav>
        </body>
        </html>
        """

        async with LLMService() as llm:
            result = await llm.classify_html_content(legitimate_html)

            assert "confidence" in result
            assert "label" in result
            assert 0 <= result["confidence"] <= 1

            print(f"✅ Legitimate Content Classification: {result}")

    @pytest.mark.asyncio
    async def test_explanation_generation(self):
        """Test LLM explanation generation"""
        async with LLMService() as llm:
            url_class = {"is_malicious": True, "confidence": 0.85, "label": "malicious"}
            content_class = {"is_phishing": True, "confidence": 0.90, "label": "phishing"}
            ssl_analysis = {"valid": False, "threat_score": 30}
            vt_analysis = {"malicious_count": 5, "suspicious_count": 2, "total_engines": 70}

            result = await llm.generate_explanation(
                "http://suspicious-site.com", url_class, content_class, ssl_analysis, vt_analysis
            )

            # Verify explanation structure
            assert "explanation" in result or "success" in result
            assert "risk_summary" in result
            assert "threat_factors" in result
            assert "recommended_action" in result

            # Verify threat factors exist for malicious site
            assert len(result["threat_factors"]) > 0

            print("✅ Explanation Generated:")
            print(f"   Risk Summary: {result['risk_summary']}")
            print(f"   Threat Factors: {result['threat_factors']}")
            print(f"   Recommended Action: {result['recommended_action']}")

    @pytest.mark.asyncio
    async def test_complete_llm_analysis(self):
        """Test complete LLM analysis pipeline"""
        async with LLMService() as llm:
            html_content = "<html><body>Verify your account now!</body></html>"
            ssl_analysis = {"valid": True}
            vt_analysis = {"malicious_count": 0, "total_engines": 70}

            result = await llm.analyze_with_llm(
                url="https://test-site.com",
                html_content=html_content,
                ssl_analysis=ssl_analysis,
                vt_analysis=vt_analysis,
            )

            # Verify complete analysis structure
            assert "llm_analysis" in result
            assert "overall_assessment" in result
            assert "models_used" in result

            # Verify LLM analysis components
            llm_analysis = result["llm_analysis"]
            assert "url_classification" in llm_analysis
            assert "content_classification" in llm_analysis
            assert "explanation" in llm_analysis

            # Verify overall assessment
            assessment = result["overall_assessment"]
            assert "is_malicious" in assessment
            assert "confidence" in assessment
            assert "risk_summary" in assessment
            assert "recommended_action" in assessment

            print("✅ Complete LLM Analysis:")
            print(f"   URL Classification: {llm_analysis['url_classification']['label']}")
            print(f"   Content Classification: {llm_analysis['content_classification']['label']}")
            print(f"   Overall Malicious: {assessment['is_malicious']}")
            print(f"   Confidence: {assessment['confidence']:.2%}")

    @pytest.mark.asyncio
    async def test_fallback_mechanisms(self):
        """Test that fallback mechanisms work when LLM is unavailable"""
        # Create LLM service with invalid API key to trigger fallback
        llm = LLMService()
        llm.api_key = "invalid_key_for_testing"

        async with llm:
            # Test URL classification fallback
            url_result = await llm.classify_url("http://suspicious-login.tk")
            assert "fallback" in url_result or "model" in url_result
            assert url_result["confidence"] >= 0

            # Test content classification fallback
            content_result = await llm.classify_html_content("Verify your account immediately!")
            assert "fallback" in content_result or "model" in content_result
            assert content_result["confidence"] >= 0

            print("✅ Fallback mechanisms working correctly")

    @pytest.mark.asyncio
    async def test_explanation_context_building(self):
        """Test explanation context building logic"""
        async with LLMService() as llm:
            context = llm._build_explanation_context(
                url="http://test.com",
                url_class={"is_malicious": True, "confidence": 0.9},
                content_class={"is_phishing": False, "confidence": 0.3},
                ssl={"valid": True},
                vt={"malicious_count": 2, "suspicious_count": 1, "total_engines": 70},
            )

            # Verify context structure
            assert "url" in context
            assert "is_threat" in context
            assert "threat_factors" in context
            assert "safety_factors" in context
            assert "recommended_action" in context
            assert "threat_level" in context

            # Should be a threat due to URL classification and VT detections
            assert context["is_threat"]
            assert len(context["threat_factors"]) > 0

            print("✅ Context Building:")
            print(f"   Is Threat: {context['is_threat']}")
            print(f"   Threat Level: {context['threat_level']}")
            print(f"   Threat Factors: {len(context['threat_factors'])}")
            print(f"   Safety Factors: {len(context['safety_factors'])}")


class TestLLMIntegration:
    """Test LLM integration with scan pipeline"""

    @pytest.mark.asyncio
    async def test_llm_data_structure(self):
        """Test that LLM returns data in expected structure"""
        async with LLMService() as llm:
            result = await llm.analyze_with_llm(
                url="https://example.com",
                html_content="<html><body>Test content</body></html>",
                ssl_analysis={"valid": True},
                vt_analysis={"malicious_count": 0, "total_engines": 70},
            )

            # Verify all required fields exist
            required_fields = ["timestamp", "url", "llm_analysis", "overall_assessment", "models_used"]

            for field in required_fields:
                assert field in result, f"Missing required field: {field}"

            # Verify nested structures
            assert "url_classification" in result["llm_analysis"]
            assert "content_classification" in result["llm_analysis"]
            assert "explanation" in result["llm_analysis"]

            assert "is_malicious" in result["overall_assessment"]
            assert "confidence" in result["overall_assessment"]

            print("✅ LLM data structure is correct")

    def test_risk_summary_generation(self):
        """Test risk summary generation"""
        llm = LLMService()

        # Test threat context
        threat_context = {"is_threat": True, "threat_factors": ["Factor 1", "Factor 2", "Factor 3"]}
        summary = llm._generate_risk_summary(threat_context)
        assert "security risks" in summary.lower() or "threat" in summary.lower()
        assert "3" in summary or "three" in summary.lower()

        # Test safe context
        safe_context = {"is_threat": False, "threat_factors": []}
        summary = llm._generate_risk_summary(safe_context)
        assert "safe" in summary.lower() or "appears" in summary.lower()

        print("✅ Risk summary generation working")


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
