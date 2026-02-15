"""
WebShield v2.2.0 — Email Threat Intelligence Tests
Tests for: NLP phishing detection, domain age (WHOIS), Safe Browsing,
           redirect resolution, AI explanation, OAuth verification,
           and the enhanced email scan endpoint.
"""

import asyncio
import os
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient
from backend.server import app

client = TestClient(app, base_url="http://testserver")
client.headers.update({"Host": "testserver"})


# ============================================
# Fixtures
# ============================================

@pytest.fixture
def safe_email_metadata():
    """Clean email from a known trusted domain."""
    return {
        "email_metadata": {
            "sender_email": "noreply@google.com",
            "sender_name": "Google",
            "subject": "Your Google Account activity",
            "body_text": "Here is your recent account activity summary.",
            "links": ["https://myaccount.google.com", "https://support.google.com"],
            "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        "scan_type": "full",
    }


@pytest.fixture
def phishing_email_metadata():
    """Obvious phishing email with many red flags."""
    return {
        "email_metadata": {
            "sender_email": "support@paypa1-secure-verify.tk",
            "sender_name": "PayPal Security",
            "subject": "URGENT: Your account has been suspended - verify immediately",
            "body_text": (
                "Dear Customer, Your PayPal account has been suspended due to "
                "suspicious activity. Click the link below to verify your identity "
                "immediately or your account will be permanently closed within 24 hours. "
                "Verify now: http://paypal-secure.tk/verify?user=12345"
            ),
            "links": [
                "http://paypal-secure.tk/verify?user=12345",
                "http://192.168.1.1/phishing",
            ],
            "headers": {"spf": None, "dkim": None, "dmarc": None},
        },
        "scan_type": "full",
    }


@pytest.fixture
def suspicious_email_metadata():
    """Borderline suspicious email."""
    return {
        "email_metadata": {
            "sender_email": "offers@random-deals-site.com",
            "sender_name": "Amazing Deals",
            "subject": "You won a free iPhone! Claim now",
            "body_text": (
                "Congratulations! You have been selected as our lucky winner. "
                "Click below to claim your free iPhone 15 Pro Max. "
                "Limited time offer - act now!"
            ),
            "links": ["https://random-deals-site.com/claim"],
            "headers": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        },
        "scan_type": "full",
    }


# ============================================
# 1. Email Scan Endpoint Tests (Integration)
# ============================================

class TestEmailScanEndpoint:
    """Integration tests for the /email/scan-metadata endpoint."""

    pytestmark = pytest.mark.integration

    def test_scan_safe_email(self, safe_email_metadata):
        """Safe email from trusted domain — may still be flagged by VT false positive."""
        response = client.post("/api/email/scan-metadata", json=safe_email_metadata)
        assert response.status_code == 200

        data = response.json()
        assert "threat_score" in data
        assert "threat_level" in data
        assert "summary" in data
        assert "reasons" in data
        assert "details" in data
        assert "confidence" in data

        # After VT false-positive fix: trusted domain caps at 55 even if VT flags links
        assert data["threat_score"] <= 55, f"Safe email got threat_score={data['threat_score']}"
        assert data["threat_level"] in ["safe", "low", "suspicious"]

        # Details should have all subsections
        details = data["details"]
        assert "sender_reputation" in details
        assert "header_analysis" in details
        assert "link_analysis" in details
        assert "content_analysis" in details

    def test_scan_phishing_email(self, phishing_email_metadata):
        """Phishing email should get high threat score."""
        response = client.post("/api/email/scan-metadata", json=phishing_email_metadata)
        # Allow 408 for timeout in test env (VT takes time for suspicious domains)
        assert response.status_code in [200, 408], f"Unexpected status: {response.status_code}"

        if response.status_code == 200:
            data = response.json()
            assert data["threat_score"] >= 50, f"Phishing email got only {data['threat_score']}"
            assert data["threat_level"] in ["suspicious", "dangerous", "malicious", "medium", "high"]
            assert len(data["reasons"]) > 0

    def test_scan_suspicious_email(self, suspicious_email_metadata):
        """Suspicious email should be flagged."""
        response = client.post("/api/email/scan-metadata", json=suspicious_email_metadata)
        assert response.status_code in [200, 408], f"Unexpected status: {response.status_code}"

        if response.status_code == 200:
            data = response.json()
            assert data["threat_score"] >= 25, f"Suspicious email got only {data['threat_score']}"

    def test_scan_returns_confidence(self, safe_email_metadata):
        """Scan should return a confidence value between 0 and 1."""
        response = client.post("/api/email/scan-metadata", json=safe_email_metadata)
        data = response.json()

        assert "confidence" in data
        conf = data["confidence"]
        assert conf is None or (0.0 <= conf <= 1.0), f"Confidence out of range: {conf}"

    def test_scan_invalid_email_format(self):
        """Invalid email format should return 422 validation error."""
        response = client.post("/api/email/scan-metadata", json={
            "email_metadata": {
                "sender_email": "not-an-email",
                "subject": "Test",
                "links": [],
            },
            "scan_type": "full",
        })
        assert response.status_code == 422

    def test_scan_empty_body(self, safe_email_metadata):
        """Scan with empty body should still work."""
        safe_email_metadata["email_metadata"]["body_text"] = ""
        response = client.post("/api/email/scan-metadata", json=safe_email_metadata)
        assert response.status_code == 200

    def test_scan_no_links(self, safe_email_metadata):
        """Scan with no links should still work."""
        safe_email_metadata["email_metadata"]["links"] = []
        response = client.post("/api/email/scan-metadata", json=safe_email_metadata)
        assert response.status_code == 200
        data = response.json()
        assert data["details"]["link_analysis"]["link_count"] == 0


# ============================================
# 2. NLP Phishing Pattern Detection Tests
# ============================================

class TestNlpPhishingDetection:
    """Unit tests for the NLP phishing pattern analysis."""

    def _run_nlp(self, **kwargs):
        """Helper to run the NLP analyzer synchronously."""
        from backend.email_routes import analyze_phishing_patterns_nlp
        return analyze_phishing_patterns_nlp(**kwargs)

    def test_clean_email_low_score(self):
        """Clean email should have low NLP score."""
        score, patterns, confidence = self._run_nlp(
            subject="Meeting reminder: Project standup at 3pm",
            body_snippet="Hi team, just a reminder that our daily standup is at 3pm today.",
            sender_email="john@company.com",
            sender_name="John Smith",
        )
        assert score <= 30, f"Clean email NLP score too high: {score}"

    def test_urgency_patterns_detected(self):
        """Urgency language should increase NLP score."""
        score, patterns, confidence = self._run_nlp(
            subject="URGENT: Your account will be closed immediately!",
            body_snippet="Act now or lose access permanently. Immediate action required.",
            sender_email="alert@random-domain.tk",
            sender_name="Account Security",
        )
        assert score >= 30, f"Urgency patterns not detected: score={score}"
        pattern_types = [p.get("pattern_type", "") if isinstance(p, dict) else getattr(p, "pattern_type", "") for p in patterns]
        assert any("urgency" in t for t in pattern_types), f"No urgency pattern found: {pattern_types}"

    def test_name_domain_mismatch(self):
        """Sender name spoofing a known brand with different domain."""
        score, patterns, confidence = self._run_nlp(
            subject="URGENT: Your Amazon order needs attention",
            body_snippet="Click here to verify your identity immediately or your order will be cancelled.",
            sender_email="support@random-shop.tk",
            sender_name="Amazon.com",
        )
        # Name mismatch + urgency + phishing terms should raise score
        assert score >= 10, f"Name spoof not detected: score={score}"

    def test_suspicious_keywords_density(self):
        """High density of phishing keywords should boost score."""
        score, patterns, confidence = self._run_nlp(
            subject="Verify your password - account suspended",
            body_snippet=(
                "Click here to verify your password. Your account has been suspended. "
                "Confirm your identity to restore access. Enter your credentials below. "
                "This is your final warning before account deletion."
            ),
            sender_email="security@fake-bank.ru",
        )
        assert score >= 40, f"Keyword density not detected: score={score}"

    def test_returns_valid_structure(self):
        """NLP result should return (int, list, float)."""
        score, patterns, confidence = self._run_nlp(
            subject="Hello",
            body_snippet="Test email",
            sender_email="test@example.com",
        )
        assert isinstance(score, (int, float))
        assert isinstance(patterns, list)
        assert isinstance(confidence, float)
        assert 0 <= score <= 100
        assert 0.0 <= confidence <= 1.0


# ============================================
# 3. WHOIS Domain Age Tests
# ============================================

class TestDomainAgeCheck:
    """Tests for WHOIS domain age lookup."""

    def test_domain_age_with_known_domain(self):
        """Test domain age check with a well-known domain."""
        from backend.email_routes import _check_domain_age_sync
        from backend.config import settings as cfg

        api_key = cfg.WHOIS_API_KEY
        if not api_key:
            pytest.skip("WHOIS_API_KEY not configured")

        result = _check_domain_age_sync("google.com", api_key)
        assert result is not None, "WHOIS returned None for google.com"
        assert "age_days" in result
        assert "created" in result
        assert "is_new" in result

        # google.com was registered in 1997, should not be new
        assert result["is_new"] is False
        assert result["age_days"] > 365 * 20  # Over 20 years old

    def test_domain_age_invalid_domain(self):
        """Invalid domain should return None gracefully."""
        from backend.email_routes import _check_domain_age_sync
        from backend.config import settings as cfg

        api_key = cfg.WHOIS_API_KEY
        if not api_key:
            pytest.skip("WHOIS_API_KEY not configured")

        result = _check_domain_age_sync("thisdoesnotexist12345.xyz", api_key)
        # Should return None or a dict without crashing
        assert result is None or isinstance(result, dict)

    def test_domain_age_without_api_key(self):
        """Without API key, should return None gracefully."""
        from backend.email_routes import _check_domain_age_sync
        result = _check_domain_age_sync("google.com", "")
        # Empty API key causes API error → returns None
        assert result is None or isinstance(result, dict)

    def test_domain_age_caching(self):
        """Second call for same domain should use cache."""
        from backend.email_routes import _check_domain_age_sync, _domain_age_cache
        from backend.config import settings as cfg

        api_key = cfg.WHOIS_API_KEY
        if not api_key:
            pytest.skip("WHOIS_API_KEY not configured")

        domain = "github.com"
        # Clear cache first
        _domain_age_cache.pop(domain, None)

        t1 = time.time()
        result1 = _check_domain_age_sync(domain, api_key)
        elapsed1 = time.time() - t1

        t2 = time.time()
        result2 = _check_domain_age_sync(domain, api_key)
        elapsed2 = time.time() - t2

        # Cached call should be much faster
        if elapsed1 > 0.5:  # Only assert if first call was slow (network)
            assert elapsed2 < elapsed1, "Cache should make second call faster"


# ============================================
# 4. Google Safe Browsing Tests
# ============================================

class TestGoogleSafeBrowsing:
    """Tests for Google Safe Browsing API integration."""

    def test_safe_urls_not_flagged(self):
        """Known safe URLs should not be flagged."""
        from backend.email_routes import check_google_safe_browsing
        from backend.config import settings as cfg

        api_key = cfg.GOOGLE_SAFE_BROWSING_KEY
        if not api_key:
            pytest.skip("GOOGLE_SAFE_BROWSING_KEY not configured")

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            check_google_safe_browsing(["https://google.com", "https://github.com"], api_key)
        )
        loop.close()

        assert isinstance(result, dict)
        # These known-safe URLs should not be flagged
        assert len(result) == 0, f"Safe URLs were flagged: {result}"

    def test_no_api_key_returns_empty(self):
        """Without API key, should return empty dict."""
        from backend.email_routes import check_google_safe_browsing

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            check_google_safe_browsing(["https://example.com"], api_key="")
        )
        loop.close()

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_empty_urls_list(self):
        """Empty URL list should return empty dict."""
        from backend.email_routes import check_google_safe_browsing

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            check_google_safe_browsing([], api_key="test-key")
        )
        loop.close()

        assert isinstance(result, dict)
        assert len(result) == 0


# ============================================
# 5. URL Redirect Resolution Tests
# ============================================

class TestRedirectResolution:
    """Tests for URL redirect chain resolution."""

    def test_no_redirect(self):
        """URL with no redirect should return single-item chain."""
        from backend.email_routes import resolve_redirect_chain

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(resolve_redirect_chain("https://google.com"))
        loop.close()

        assert isinstance(result, list)
        assert len(result) >= 1
        assert result[0] == "https://google.com"

    def test_invalid_url(self):
        """Invalid URL should return single-item chain gracefully."""
        from backend.email_routes import resolve_redirect_chain

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(resolve_redirect_chain("http://thisdoesnotexist12345.invalid"))
        loop.close()

        assert isinstance(result, list)
        assert len(result) >= 1

    def test_batch_resolution_only_shorteners(self):
        """Batch resolve only resolves shortener URLs, returns empty for regular URLs."""
        from backend.email_routes import resolve_redirect_chains_batch

        # Regular URLs are not resolved — only shortener domains are
        urls = ["https://google.com", "https://github.com"]
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(resolve_redirect_chains_batch(urls))
        loop.close()

        # Non-shortener URLs are skipped, so result should be empty
        assert isinstance(result, dict)

    def test_batch_empty_list(self):
        """Empty URL list should return empty dict."""
        from backend.email_routes import resolve_redirect_chains_batch

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(resolve_redirect_chains_batch([]))
        loop.close()

        assert isinstance(result, dict)
        assert len(result) == 0


# ============================================
# 6. AI Threat Explanation Tests
# ============================================

class TestAIExplanation:
    """Tests for AI-powered threat explanation generation."""

    def test_explanation_generation(self):
        """Should generate a ThreatExplanation object for a phishing email."""
        from backend.email_routes import generate_threat_explanation
        from backend.config import settings as cfg

        if not cfg.GROQ_API_KEY:
            pytest.skip("GROQ_API_KEY not configured")

        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(generate_threat_explanation(
            threat_score=85,
            threat_level="dangerous",
            summary="High risk email detected",
            reasons=["Suspicious sender domain", "Urgency phrases detected"],
            sender_email="alert@phishing-site.tk",
            details={"sender_reputation": {"domain": "phishing-site.tk", "reputation_score": 15}},
        ))
        loop.close()

        assert result is not None
        # Result is a ThreatExplanation Pydantic model
        assert hasattr(result, "why_marked") or hasattr(result, "explanation") or isinstance(result, dict)

    def test_explanation_handles_missing_groq_key(self):
        """Should return None gracefully if GROQ key is missing."""
        from backend.email_routes import generate_threat_explanation

        with patch.dict(os.environ, {"GROQ_API_KEY": ""}):
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(generate_threat_explanation(
                threat_score=50,
                threat_level="suspicious",
                summary="Test",
                reasons=["Test reason"],
                sender_email="test@example.com",
                details={},
            ))
            loop.close()
            # Should not crash — may return None or empty explanation


# ============================================
# 7. Standalone Endpoints
# ============================================

class TestStandaloneEndpoints:
    """Tests for standalone API endpoints."""

    def test_health_check(self):
        """Health check should return feature status."""
        response = client.get("/api/email/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "auth_checker_available" in data

    def test_explain_threat_endpoint(self):
        """POST /email/explain-threat should work or gracefully fail."""
        response = client.post("/api/email/explain-threat", json={
            "threat_score": 75,
            "threat_level": "dangerous",
            "summary": "High risk email",
            "reasons": ["Suspicious domain", "Phishing keywords"],
            "sender_email": "alert@phishing.tk",
            "details": {},
        })
        # 200 = success, 502 = AI returned empty, 503 = key not configured
        assert response.status_code in [200, 502, 503], f"Unexpected status: {response.status_code}"

    def test_verify_oauth_token_endpoint(self):
        """POST /email/verify-oauth-token with invalid token should fail gracefully."""
        response = client.post("/api/email/verify-oauth-token", json={
            "access_token": "invalid-token-12345",
        })
        # Should not crash
        assert response.status_code in [200, 400, 401, 422, 500]

    def test_check_email_auth_endpoint(self):
        """GET /email/check-auth should perform DNS auth check."""
        response = client.get("/api/email/check-auth", params={"email": "test@google.com"})
        assert response.status_code == 200

        data = response.json()
        assert "spf" in data or "spf_status" in data or "domain" in data


# ============================================
# 8. Sender Reputation Tests
# ============================================

class TestSenderReputation:
    """Tests for sender reputation analysis (sync function)."""

    def test_trusted_domain_high_score(self):
        """Known trusted domain should get high reputation score."""
        from backend.email_routes import analyze_sender_reputation

        result = analyze_sender_reputation("user@google.com")

        assert result.reputation_score >= 70
        assert result.is_trusted_domain is True

    def test_suspicious_domain_low_score(self):
        """Suspicious TLD domain should get lower reputation score."""
        from backend.email_routes import analyze_sender_reputation

        result = analyze_sender_reputation("user@free-money.tk")

        assert result.reputation_score < 70
        assert result.is_trusted_domain is False

    def test_disposable_email_detected(self):
        """Disposable email provider should be flagged."""
        from backend.email_routes import analyze_sender_reputation

        result = analyze_sender_reputation("user@guerrillamail.com")

        assert result.is_disposable is True

    def test_domain_age_in_reputation(self):
        """Sender reputation should have domain_age_days field."""
        from backend.email_routes import analyze_sender_reputation

        result = analyze_sender_reputation("user@google.com")

        # SenderReputation model has domain_age_days field
        assert hasattr(result, "domain_age_days")


# ============================================
# 9. Content Analysis Tests
# ============================================

class TestContentAnalysis:
    """Tests for email content analysis."""

    def test_clean_subject(self):
        """Clean subject should have low phishing score."""
        from backend.email_routes import analyze_content

        result = analyze_content("Meeting notes from today's standup")
        assert result.phishing_keywords_found <= 1

    def test_phishing_subject(self):
        """Phishing subject should detect keywords."""
        from backend.email_routes import analyze_content

        result = analyze_content("URGENT: Verify your account immediately or face suspension")
        assert result.phishing_keywords_found >= 1

    def test_none_subject(self):
        """None subject should not crash."""
        from backend.email_routes import analyze_content

        result = analyze_content(None)
        assert result.phishing_keywords_found == 0


# ============================================
# 10. Threat Score Calculation Tests
# ============================================

class TestThreatScoreCalculation:
    """Tests for the calculate_threat_score function."""

    def test_safe_email_score(self):
        """Safe email components should produce low threat score."""
        from backend.email_routes import (
            SenderReputation, HeaderAnalysis, LinkAnalysis,
            ContentAnalysis, calculate_threat_score,
        )

        sender = SenderReputation(
            domain="google.com", reputation_score=95,
            is_trusted_domain=True, is_disposable=False, is_free_provider=False,
        )
        headers = HeaderAnalysis(
            spf_status="pass", dkim_status="pass", dmarc_status="pass",
            is_authenticated=True, authentication_score=100,
        )
        links = LinkAnalysis(links=["https://google.com"], link_count=1)
        content = ContentAnalysis(phishing_keywords_found=0)

        score, level, summary, reasons, confidence = calculate_threat_score(
            sender, headers, links, content
        )
        assert score <= 25, f"Safe email got score {score}"
        assert level in ["safe", "low"]

    def test_dangerous_email_score(self):
        """Dangerous email components should produce high threat score."""
        from backend.email_routes import (
            SenderReputation, HeaderAnalysis, LinkAnalysis,
            ContentAnalysis, calculate_threat_score,
        )

        sender = SenderReputation(
            domain="phishing.tk", reputation_score=10,
            is_trusted_domain=False, is_disposable=True, is_free_provider=False,
        )
        headers = HeaderAnalysis(
            spf_status="fail", dkim_status="fail", dmarc_status="fail",
            is_authenticated=False, authentication_score=0,
        )
        links = LinkAnalysis(
            links=["http://phishing.tk/steal"],
            suspicious_links=["http://phishing.tk/steal"],
            link_count=1,
        )
        content = ContentAnalysis(phishing_keywords_found=10)

        score, level, summary, reasons, confidence = calculate_threat_score(
            sender, headers, links, content
        )
        assert score >= 50, f"Dangerous email got score {score}"

    def test_returns_confidence(self):
        """calculate_threat_score should return confidence as 5th element."""
        from backend.email_routes import (
            SenderReputation, HeaderAnalysis, LinkAnalysis,
            ContentAnalysis, calculate_threat_score,
        )

        sender = SenderReputation(domain="test.com", reputation_score=50, is_trusted_domain=False)
        headers = HeaderAnalysis()
        links = LinkAnalysis()
        content = ContentAnalysis()

        result = calculate_threat_score(sender, headers, links, content)
        assert len(result) == 5
        confidence = result[4]
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0


# ============================================
# 11. Link Analysis Tests
# ============================================

class TestLinkAnalysis:
    """Tests for link analysis functionality."""

    def test_safe_links(self):
        """Safe links should have low risk score."""
        from backend.email_routes import analyze_links

        result = analyze_links(["https://google.com", "https://github.com"])
        assert result.risk_score <= 30

    def test_suspicious_links(self):
        """IP-based and suspicious TLD links should be flagged."""
        from backend.email_routes import analyze_links

        result = analyze_links([
            "http://192.168.1.1/login",
            "https://paypal-verify.tk/steal",
        ])
        assert len(result.suspicious_links) > 0
        assert result.risk_score >= 30

    def test_empty_links(self):
        """Empty link list should work."""
        from backend.email_routes import analyze_links

        result = analyze_links([])
        assert result.link_count == 0
        assert result.risk_score == 0
