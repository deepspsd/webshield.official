"""
WebShield v2.2.0 — Quick Smoke Test
Run directly: python tests/test_v22_smoke.py

Tests all new v2.2 features against a running server at localhost:8000.
No pytest needed — just plain requests.
"""

import json
import os
import sys
import time
from pathlib import Path

# Fix Windows console encoding for emoji output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add project root
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import requests
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

BASE_URL = os.environ.get("WEBSHIELD_URL", "http://localhost:8000")
API = f"{BASE_URL}/api"

PASS = "✅"
FAIL = "❌"
SKIP = "⏭️"
results = []


def test(name, fn):
    """Run a single test and record result."""
    try:
        fn()
        results.append((PASS, name))
        print(f"  {PASS} {name}")
    except AssertionError as e:
        results.append((FAIL, f"{name}: {e}"))
        print(f"  {FAIL} {name}: {e}")
    except Exception as e:
        results.append((FAIL, f"{name}: {type(e).__name__}: {e}"))
        print(f"  {FAIL} {name}: {type(e).__name__}: {e}")


def skip(name, reason):
    results.append((SKIP, f"{name} ({reason})"))
    print(f"  {SKIP} {name} ({reason})")


# ============================================
# 1. Health Check
# ============================================
print("\n🏥 Health Check")


def test_health():
    r = requests.get(f"{API}/email/health", timeout=10)
    assert r.status_code == 200, f"Status {r.status_code}"
    data = r.json()
    assert data["status"] == "healthy", f"Status: {data['status']}"
    print(f"     Features: auth_checker={data.get('auth_checker_available')}, "
          f"safe_browsing={data.get('features', {}).get('safe_browsing')}, "
          f"domain_age={data.get('features', {}).get('whois_domain_age')}, "
          f"nlp={data.get('features', {}).get('nlp_analysis')}")


test("Health endpoint returns healthy", test_health)

# ============================================
# 2. Safe Email Scan
# ============================================
print("\n📧 Safe Email Scan")


def test_safe_scan():
    r = requests.post(f"{API}/email/scan-metadata", json={
        "email_metadata": {
            "sender_email": "noreply@google.com",
            "sender_name": "Google",
            "subject": "Your Google Account activity summary",
            "body_text": "Here is your recent account activity for the month.",
            "links": ["https://myaccount.google.com"],
            "headers": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        },
        "scan_type": "full",
    }, timeout=30)
    assert r.status_code == 200, f"Status {r.status_code}: {r.text[:200]}"
    data = r.json()

    print(f"     Threat Score: {data.get('threat_score')}")
    print(f"     Threat Level: {data.get('threat_level')}")
    print(f"     Confidence:   {data.get('confidence')}")
    print(f"     Reasons:      {data.get('reasons', [])[:3]}")

    assert data["threat_score"] <= 55, f"Safe email got score {data['threat_score']}"
    assert data["threat_level"] in ["safe", "low", "suspicious"], f"Level: {data['threat_level']}"


test("Safe email from google.com → low threat score", test_safe_scan)

# ============================================
# 3. Phishing Email Scan
# ============================================
print("\n🎣 Phishing Email Scan")


def test_phishing_scan():
    r = requests.post(f"{API}/email/scan-metadata", json={
        "email_metadata": {
            "sender_email": "security@paypa1-verify.tk",
            "sender_name": "PayPal Security Team",
            "subject": "URGENT: Your account will be suspended - verify now",
            "body_text": (
                "Dear customer, your PayPal account has been flagged for suspicious activity. "
                "Click here to verify your identity immediately or your account will be "
                "permanently closed within 24 hours. Enter your password to confirm."
            ),
            "links": [
                "http://paypal-verify.tk/steal-credentials",
                "http://192.168.1.1/fake-login",
            ],
            "headers": {"spf": None, "dkim": None, "dmarc": None},
        },
        "scan_type": "full",
    }, timeout=30)
    assert r.status_code == 200, f"Status {r.status_code}: {r.text[:200]}"
    data = r.json()

    print(f"     Threat Score: {data.get('threat_score')}")
    print(f"     Threat Level: {data.get('threat_level')}")
    print(f"     Confidence:   {data.get('confidence')}")
    print(f"     Reasons:      {json.dumps(data.get('reasons', [])[:5], indent=8)}")

    # Check new fields
    details = data.get("details", {})
    content = details.get("content_analysis", {})
    sender = details.get("sender_reputation", {})
    links = details.get("link_analysis", {})

    print(f"     NLP Score:    {content.get('nlp_score', 'N/A')}")
    print(f"     NLP Confidence: {content.get('nlp_confidence', 'N/A')}")
    print(f"     Domain Age:   {sender.get('domain_age_days', 'N/A')} days")
    print(f"     Newly Reg:    {sender.get('is_newly_registered', 'N/A')}")
    print(f"     Safe Browsing: {links.get('safe_browsing_threats', {})}")

    # AI Explanation
    ai = data.get("ai_explanation")
    if ai:
        exp = ai.get("explanation", "")
        print(f"     AI Explain:   {exp[:100]}...")
    else:
        print(f"     AI Explain:   None (GROQ key may be missing)")

    assert data["threat_score"] >= 40, f"Phishing email got only {data['threat_score']}"


test("Phishing email → high threat score + new fields", test_phishing_scan)

# ============================================
# 4. NLP Analysis (Direct Function)
# ============================================
print("\n🧠 NLP Phishing Detection")


def test_nlp_direct():
    from backend.email_routes import analyze_phishing_patterns_nlp

    score, patterns, confidence = analyze_phishing_patterns_nlp(
        subject="URGENT: Verify your account immediately",
        body_snippet="Click here to confirm your password or face suspension.",
        sender_email="alert@fake-bank.ru",
        sender_name="Bank Security",
    )
    print(f"     NLP Score:    {score}")
    print(f"     Patterns:     {len(patterns)}")
    print(f"     Confidence:   {confidence:.2f}")
    assert score >= 20, f"NLP missed phishing signals: score={score}"
    assert isinstance(patterns, list)


test("NLP detects phishing patterns in suspicious content", test_nlp_direct)

# ============================================
# 5. Domain Age (WHOIS)
# ============================================
print("\n📅 Domain Age Check (WHOIS)")

from backend.config import settings as cfg

if cfg.WHOIS_API_KEY:
    def test_domain_age():
        from backend.email_routes import _check_domain_age_sync
        result = _check_domain_age_sync("google.com", cfg.WHOIS_API_KEY)
        print(f"     Created:      {result.get('created', 'N/A')}")
        print(f"     Age (days):   {result.get('age_days', 'N/A')}")
        print(f"     Newly Reg:    {result.get('is_new', 'N/A')}")
        assert result is not None, "WHOIS returned None — API key may be invalid"
        assert result.get('age_days', 0) > 5000, "google.com should be old"
        assert result.get('is_new') is False

    test("google.com domain age > 20 years", test_domain_age)
else:
    skip("Domain age check", "WHOIS_API_KEY not set")

# ============================================
# 6. Google Safe Browsing
# ============================================
print("\n🛡️  Google Safe Browsing")

import asyncio

if cfg.GOOGLE_SAFE_BROWSING_KEY:
    def test_safe_browsing():
        from backend.email_routes import check_google_safe_browsing
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            check_google_safe_browsing(
                ["https://google.com", "https://github.com"],
                cfg.GOOGLE_SAFE_BROWSING_KEY,
            )
        )
        loop.close()
        print(f"     Flagged URLs: {len(result)}")
        assert len(result) == 0, f"Safe URLs flagged: {result}"

    test("Safe URLs not flagged by Safe Browsing", test_safe_browsing)
else:
    skip("Safe Browsing check", "GOOGLE_SAFE_BROWSING_KEY not set")

# ============================================
# 7. Threat Score Calculation
# ============================================
print("\n📊 Threat Score Calculation")


def test_threat_score():
    from backend.email_routes import (
        SenderReputation, HeaderAnalysis, LinkAnalysis,
        ContentAnalysis, calculate_threat_score,
    )

    # Safe case
    safe_score, safe_level, _, _, safe_conf = calculate_threat_score(
        SenderReputation(domain="google.com", reputation_score=95, is_trusted_domain=True),
        HeaderAnalysis(spf_status="pass", dkim_status="pass", dmarc_status="pass",
                       is_authenticated=True, authentication_score=100),
        LinkAnalysis(links=["https://google.com"], link_count=1),
        ContentAnalysis(phishing_keywords_found=0),
    )

    # Dangerous case
    bad_score, bad_level, _, _, bad_conf = calculate_threat_score(
        SenderReputation(domain="evil.tk", reputation_score=5, is_trusted_domain=False, is_disposable=True),
        HeaderAnalysis(spf_status="fail", dkim_status="fail", is_authenticated=False),
        LinkAnalysis(links=["http://evil.tk"], suspicious_links=["http://evil.tk"], link_count=1),
        ContentAnalysis(phishing_keywords_found=10),
    )

    print(f"     Safe score:     {safe_score} ({safe_level}, conf={safe_conf:.2f})")
    print(f"     Dangerous score: {bad_score} ({bad_level}, conf={bad_conf:.2f})")

    assert safe_score < bad_score, f"Safe({safe_score}) >= Bad({bad_score})"
    assert safe_score <= 30
    assert bad_score >= 50


test("Safe < Dangerous score ordering", test_threat_score)

# ============================================
# 8. AI Explanation Endpoint
# ============================================
print("\n🤖 AI Explain Threat Endpoint")


def test_explain_endpoint():
    r = requests.post(f"{API}/email/explain-threat", json={
        "threat_score": 80,
        "threat_level": "dangerous",
        "summary": "High risk email detected",
        "reasons": ["Suspicious sender", "Phishing keywords detected"],
        "sender_email": "phishing@evil.tk",
        "details": {},
    }, timeout=30)
    assert r.status_code == 200, f"Status {r.status_code}"
    data = r.json()
    print(f"     Response keys: {list(data.keys())}")


test("Explain threat endpoint responds 200", test_explain_endpoint)

# ============================================
# Summary
# ============================================
print("\n" + "=" * 50)
passed = sum(1 for r in results if r[0] == PASS)
failed = sum(1 for r in results if r[0] == FAIL)
skipped = sum(1 for r in results if r[0] == SKIP)
total = len(results)

print(f"Results: {passed}/{total} passed, {failed} failed, {skipped} skipped")

if failed > 0:
    print(f"\n{FAIL} FAILURES:")
    for status, name in results:
        if status == FAIL:
            print(f"   {name}")

print("=" * 50)
sys.exit(1 if failed > 0 else 0)
