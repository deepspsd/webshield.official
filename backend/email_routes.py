"""
Email Scanning Routes for Gmail Extension
Provides email-specific threat analysis endpoints with real SPF/DMARC verification,
Google Safe Browsing, WHOIS domain age, NLP phishing detection, and AI explanations
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

from .utils import WebShieldDetector

try:
    from .auth_checker import check_email_authentication, check_email_authentication_async

    AUTH_CHECKER_AVAILABLE = True
except ImportError:
    AUTH_CHECKER_AVAILABLE = False
    logging.warning("auth_checker not available, using fallback auth analysis")

logger = logging.getLogger(__name__)

email_router = APIRouter(prefix="/email", tags=["Email"])


AUTH_CACHE: Dict[str, Tuple[dict, float]] = {}
AUTH_CACHE_TTL_SECONDS = 86400


def _now_s() -> float:
    return time.time()


def _normalize_scan_type(scan_type: Optional[str]) -> str:
    s = (scan_type or "quick").strip().lower()
    return "full" if s == "full" else "quick"


def _extract_sender_domain(sender_email: str) -> str:
    if not sender_email or "@" not in sender_email:
        return ""
    return sender_email.split("@", 1)[1].lower().strip()


def _dedupe_and_limit_links(links: List[str], limit: int) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for l in links or []:
        if not isinstance(l, str):
            continue
        s = l.strip()
        if not s or s in seen:
            continue
        out.append(s)
        seen.add(s)
        if len(out) >= limit:
            break
    return out


def _get_cached_auth(domain: str) -> Optional[dict]:
    if not domain:
        return None
    try:
        entry = AUTH_CACHE.get(domain)
        if not entry:
            return None
        payload, ts = entry
        if (_now_s() - float(ts or 0)) <= AUTH_CACHE_TTL_SECONDS and isinstance(payload, dict):
            return dict(payload)
        AUTH_CACHE.pop(domain, None)
        return None
    except Exception:
        return None


def _set_cached_auth(domain: str, payload: dict) -> None:
    if not domain or not isinstance(payload, dict):
        return
    try:
        AUTH_CACHE[domain] = (dict(payload), _now_s())
    except Exception:
        return


def _build_minimal_details(
    *,
    sender_rep: Optional[SenderReputation] = None,
    header_analysis: Optional[HeaderAnalysis] = None,
    link_analysis: Optional[LinkAnalysis] = None,
    content_analysis: Optional[ContentAnalysis] = None,
) -> EmailScanDetails:
    sr = sender_rep or SenderReputation(
        domain="",
        reputation_score=50,
        is_trusted_domain=False,
        domain_age_days=None,
        domain_created=None,
        is_newly_registered=False,
        is_disposable=False,
        is_free_provider=False,
    )
    ha = header_analysis or HeaderAnalysis(
        spf_status="unknown",
        dkim_status="unknown",
        dmarc_status="unknown",
        spf_posture="unknown",
        dkim_posture="unknown",
        dmarc_posture="unknown",
        is_authenticated=False,
        authentication_score=50,
        gmail_api_verified=False,
        reply_to=None,
        return_path=None,
        received=[],
        authentication_results=None,
    )
    la = link_analysis or LinkAnalysis(
        links=[],
        suspicious_links=[],
        malicious_links=[],
        vt_suspicious_links=[],
        vt_malicious_links=[],
        vt_scanned_links=0,
        vt_scan_timed_out=False,
        safe_browsing_threats={},
        redirect_chains={},
        link_count=0,
        risk_score=0,
        link_scan_results={},
    )
    ca = content_analysis or ContentAnalysis(
        phishing_keywords_found=0,
        detected_keywords=[],
        nlp_score=0,
        nlp_patterns=[],
        nlp_confidence=0.0,
    )
    return EmailScanDetails(
        sender_reputation=sr,
        header_analysis=ha,
        link_analysis=la,
        content_analysis=ca,
        attachments=[],
        has_dangerous_attachments=False,
    )


# Request/Response Models
class EmailHeaders(BaseModel):
    """Email authentication headers"""

    spf: Optional[str] = Field(None, description="SPF status")
    dkim: Optional[str] = Field(None, description="DKIM status")
    dmarc: Optional[str] = Field(None, description="DMARC status")
    via: Optional[str] = Field(None, description="Via header")
    reply_to: Optional[str] = Field(None, description="Reply-To header")
    return_path: Optional[str] = Field(None, description="Return-Path header")
    received: Optional[List[str]] = Field(None, description="Received headers")
    authentication_results: Optional[str] = Field(None, description="Authentication-Results header")


class GmailApiAuth(BaseModel):
    """Gmail API authentication data - untrusted client input that requires server validation"""
    spf: Optional[str] = Field(None, description="SPF status from Gmail API")
    dkim: Optional[str] = Field(None, description="DKIM status from Gmail API")
    dmarc: Optional[str] = Field(None, description="DMARC status from Gmail API")
    
    class Config:
        extra = "forbid"  # Reject unknown fields


class EmailMetadata(BaseModel):
    """Email metadata for scanning"""

    sender_email: EmailStr = Field(..., description="Sender email address")
    sender_name: Optional[str] = Field(None, description="Sender display name")
    subject: Optional[str] = Field(None, description="Email subject")
    links: List[str] = Field(default_factory=list, description="URLs found in email")
    attachment_hashes: List[str] = Field(default_factory=list, description="Attachment file hashes")
    attachment_names: List[str] = Field(default_factory=list, description="Attachment file names")
    attachments: List[Dict[str, Any]] = Field(default_factory=list, description="Attachment objects")
    has_dangerous_attachments: bool = Field(False, description="Whether dangerous attachment types were detected")
    headers: Optional[EmailHeaders] = Field(None, description="Email headers")
    user_email: Optional[EmailStr] = Field(None, description="Recipient email address")
    gmail_message_id: Optional[str] = Field(None, description="Gmail message ID")
    thread_id: Optional[str] = Field(None, description="Gmail thread ID")
    # NOTE: gmail_api_auth is untrusted client data and is NOT used for auto-verification.
    # Server-side verification via Gmail API or DNS lookups is required before trusting auth data.
    gmail_api_auth: Optional[GmailApiAuth] = Field(None, description="Untrusted Gmail API auth data from client - requires server validation")


class EmailScanRequest(BaseModel):
    """Request to scan email metadata"""

    email_metadata: EmailMetadata = Field(..., description="Email metadata to scan")
    scan_type: str = Field("quick", description="Type of scan (full, quick)")


class SenderReputation(BaseModel):
    """Sender reputation analysis"""

    domain: str = Field("", description="Sender domain")
    reputation_score: int = Field(..., description="Reputation score 0-100")
    is_trusted_domain: bool = Field(..., description="Whether domain is trusted")
    domain_age_days: Optional[int] = Field(None, description="Domain age in days")
    domain_created: Optional[str] = Field(None, description="Domain creation date")
    is_newly_registered: bool = Field(False, description="Whether domain is < 30 days old")
    is_disposable: bool = Field(False, description="Whether email is from disposable provider")
    is_free_provider: bool = Field(False, description="Whether email is from free provider")


class HeaderAnalysis(BaseModel):
    """Email header authentication analysis"""

    spf_status: str = Field("unknown", description="SPF check status")
    dkim_status: str = Field("unknown", description="DKIM check status")
    dmarc_status: str = Field("unknown", description="DMARC check status")
    spf_posture: str = Field("unknown", description="SPF DNS posture (configured/weak/unknown)")
    dkim_posture: str = Field("unknown", description="DKIM DNS posture (configured/missing/unknown)")
    dmarc_posture: str = Field("unknown", description="DMARC DNS posture (reject/quarantine/none/missing/unknown)")
    is_authenticated: bool = Field(False, description="Overall authentication status")
    authentication_score: int = Field(0, description="Authentication score 0-100")
    gmail_api_verified: bool = Field(False, description="Whether SPF/DKIM/DMARC were verified via Gmail API OAuth headers")
    reply_to: Optional[str] = Field(None, description="Reply-To header")
    return_path: Optional[str] = Field(None, description="Return-Path header")
    received: List[str] = Field(default_factory=list, description="Received headers")
    authentication_results: Optional[str] = Field(None, description="Authentication-Results header")


class LinkAnalysis(BaseModel):
    """Link analysis results"""

    links: List[str] = Field(default_factory=list, description="Links found")
    suspicious_links: List[str] = Field(default_factory=list, description="Suspicious links")
    malicious_links: List[str] = Field(default_factory=list, description="Malicious links")
    vt_suspicious_links: List[str] = Field(default_factory=list, description="Links flagged suspicious by VirusTotal")
    vt_malicious_links: List[str] = Field(default_factory=list, description="Links flagged malicious by VirusTotal")
    vt_scanned_links: int = Field(0, description="Number of links scanned via VirusTotal")
    vt_scan_timed_out: bool = Field(False, description="Whether VirusTotal scanning timed out")
    safe_browsing_threats: Dict[str, List[str]] = Field(default_factory=dict, description="Google Safe Browsing threats per URL")
    redirect_chains: Dict[str, List[str]] = Field(default_factory=dict, description="URL redirect chains")
    link_count: int = Field(0, description="Total link count")
    risk_score: int = Field(0, description="Link risk score 0-100")
    link_scan_results: Dict[str, dict] = Field(default_factory=dict, description="Per-link scan results")


class NlpPatternResult(BaseModel):
    """Single NLP pattern detection result"""
    pattern_type: str = Field(..., description="Type of pattern detected")
    description: str = Field("", description="Human-readable description")
    severity: str = Field("low", description="low/medium/high/critical")
    confidence: float = Field(0.0, description="0.0-1.0 confidence score")
    matched_text: str = Field("", description="Text that triggered the pattern")


class ContentAnalysis(BaseModel):
    """Content analysis results"""

    phishing_keywords_found: int = Field(0, description="Count of phishing keywords found")
    detected_keywords: List[str] = Field(default_factory=list, description="Detected phishing keywords")
    nlp_score: int = Field(0, description="NLP phishing pattern score 0-100")
    nlp_patterns: List[NlpPatternResult] = Field(default_factory=list, description="Detected NLP phishing patterns")
    nlp_confidence: float = Field(0.0, description="Overall NLP pattern confidence")


class EmailScanDetails(BaseModel):
    """Detailed scan results"""

    sender_reputation: SenderReputation
    header_analysis: HeaderAnalysis
    link_analysis: LinkAnalysis
    content_analysis: ContentAnalysis
    attachments: List[Dict[str, Any]] = Field(default_factory=list, description="Attachment objects")
    has_dangerous_attachments: bool = Field(False, description="Whether dangerous attachment types were detected")


class ThreatExplanation(BaseModel):
    """AI-generated threat explanation"""
    why_marked: str = Field("", description="Why the email was marked at this threat level")
    factor_breakdown: List[Dict[str, Any]] = Field(default_factory=list, description="Individual factor scores")
    confidence_explanation: str = Field("", description="Explanation of confidence level")
    recommendations: List[str] = Field(default_factory=list, description="Recommended actions")


class EmailScanResponse(BaseModel):
    """Response from email scan"""

    threat_score: int = Field(..., description="Overall threat score 0-100")
    threat_level: str = Field(..., description="Threat level (safe, suspicious, malicious)")
    summary: str = Field(..., description="Human-readable summary")
    reasons: List[str] = Field(default_factory=list, description="Reasons for the assessment")
    confidence: float = Field(0.85, description="Overall confidence 0.0-1.0")
    details: EmailScanDetails = Field(..., description="Detailed analysis")
    ai_explanation: Optional[ThreatExplanation] = Field(None, description="AI-generated threat explanation")
    scanned_at: datetime = Field(default_factory=datetime.now, description="Scan timestamp")


# Helper Functions
def analyze_sender_reputation(sender_email: str, sender_name: Optional[str] = None) -> SenderReputation:
    """Analyze sender reputation with comprehensive checks"""
    domain = sender_email.split("@")[1].lower() if "@" in sender_email else ""
    local_part = sender_email.split("@")[0].lower() if "@" in sender_email else ""

    # Trusted domains (major companies, organizations)
    trusted_domains = {
        # Tech giants
        "google.com",
        "gmail.com",
        "microsoft.com",
        "outlook.com",
        "apple.com",
        "amazon.com",
        "aws.amazon.com",
        "facebook.com",
        "meta.com",
        "instagram.com",
        "linkedin.com",
        "twitter.com",
        "x.com",
        "github.com",
        "gitlab.com",
        # Financial services
        "paypal.com",
        "stripe.com",
        "visa.com",
        "mastercard.com",
        "americanexpress.com",
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        # Enterprise/SaaS
        "salesforce.com",
        "adobe.com",
        "dropbox.com",
        "slack.com",
        "zoom.us",
        "atlassian.com",
        "jira.com",
        "notion.so",
        "figma.com",
        "canva.com",
        # E-commerce
        "ebay.com",
        "shopify.com",
        "etsy.com",
        "walmart.com",
        "target.com",
        # Streaming
        "netflix.com",
        "spotify.com",
        "hulu.com",
        "disney.com",
        # Other trusted
        "gov",
        "edu",
        "mil",  # Government, education, military TLDs
        # Indian Banks (official domains)
        "sbi.co.in",
        "onlinesbi.sbi",
        "hdfcbank.com",
        "hdfcbank.net",
        "icicibank.com",
        "pnb.co.in",
        "kotak.com",
        "kotaksecurities.co.in",
        "axisbank.com",
        "bankofindia.co.in",
        "bankofbaroda.co.in",
        "bankofbaroda.com",
        "unionbankofindia.co.in",
        "canarabank.com",
        "idbibank.in",
        "idbi.com",
        "indusind.com",
        "yesbank.in",
        "federalbank.co.in",
        "rbi.org.in",
        "npci.org.in",
        "paytm.com",
        "phonepe.com",
    }

    # Check if domain ends with trusted TLD
    is_trusted = domain in trusted_domains or any(domain.endswith(f".{t}") for t in ["gov", "edu", "mil"])

    # Free email providers (neutral - not suspicious but not corporate)
    free_providers = {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "icloud.com",
        "protonmail.com",
        "proton.me",
        "mail.com",
        "zoho.com",
        "yandex.com",
        "gmx.com",
        "gmx.net",
        "tutanota.com",
        "fastmail.com",
        "live.com",
        "msn.com",
        "me.com",
        "mac.com",
    }

    # Disposable email providers (comprehensive list)
    disposable_providers = {
        "tempmail.com",
        "guerrillamail.com",
        "10minutemail.com",
        "throwaway.email",
        "mailinator.com",
        "maildrop.cc",
        "temp-mail.org",
        "getnada.com",
        "fakeinbox.com",
        "sharklasers.com",
        "guerrillamail.info",
        "grr.la",
        "guerrillamail.biz",
        "guerrillamail.de",
        "guerrillamail.net",
        "guerrillamail.org",
        "spam4.me",
        "spamgourmet.com",
        "trashmail.com",
        "mytemp.email",
        "mohmal.com",
        "tempail.com",
        "burnermail.io",
        "33mail.com",
        "dispostable.com",
        "mintemail.com",
        "getairmail.com",
        "discard.email",
        "temp-mail.io",
        "tempinbox.com",
        "emailondeck.com",
        "crazymailing.com",
        "yopmail.com",
        "yopmail.fr",
        "yopmail.net",
    }

    is_free = domain in free_providers
    is_disposable = domain in disposable_providers or any(
        d in domain for d in ["tempmail", "throwaway", "disposable", "temp-mail", "fakeinbox"]
    )

    # Calculate reputation score
    # Base score for unknown domains should be NEUTRAL (50), not high.
    reputation_score = 50

    if is_trusted:
        reputation_score = 90  # Start high for trusted
    elif is_free:
        reputation_score = 45  # Slightly below neutral for free providers

    if is_disposable:
        reputation_score = 0  # Immediate fail

    # Check for suspicious patterns in sender name

    # Check for suspicious patterns in sender name
    if sender_name:
        # Severe red flags in sender name
        severe_patterns = [
            r"verify.*account",
            r"urgent.*action",
            r"suspended.*account",
            r"confirm.*identity",
            r"update.*payment",
            r"security.*alert",
            r"password.*expire",
            r"account.*locked",
            r"unusual.*activity",
            r"limited.*time",
            r"act.*now",
            r"immediate.*action",
        ]
        # Moderate red flags
        moderate_patterns = [
            r"prize",
            r"winner",
            r"congratulations",
            r"claim.*reward",
            r"free.*offer",
            r"special.*promotion",
        ]

        if any(re.search(pattern, sender_name.lower()) for pattern in severe_patterns):
            reputation_score -= 25
        elif any(re.search(pattern, sender_name.lower()) for pattern in moderate_patterns):
            reputation_score -= 10

    # Check local part (before @) for suspicious patterns
    suspicious_local_patterns = [
        r"^no-?reply$",
        r"^noreply$",
        r"support[0-9]+",
        r"service[0-9]+",
        r"[0-9]{6,}",
        r"^admin[0-9]+",
        r"^info[0-9]+",
    ]
    if any(re.search(pattern, local_part) for pattern in suspicious_local_patterns):
        reputation_score -= 5

    # Check for random-looking domain names
    if len(domain.split(".")[0]) > 15 and sum(c.isdigit() for c in domain) > 3:
        reputation_score -= 20

    # Ensure score is in valid range
    # Untrusted domains usually shouldn't exceed 60 unless we have specific positive signals (which we don't here)
    if not is_trusted:
        reputation_score = min(60, reputation_score)

    reputation_score = max(0, min(100, reputation_score))

    return SenderReputation(
        domain=domain,
        reputation_score=reputation_score,
        is_trusted_domain=is_trusted,
        domain_age_days=None,
        domain_created=None,
        is_newly_registered=False,
        is_disposable=is_disposable,
        is_free_provider=is_free,
    )


def analyze_content(subject: Optional[str]) -> ContentAnalysis:
    """Lightweight content analysis (subject-only) for Gmail extension reports."""

    text = (subject or "").lower()
    if not text:
        return ContentAnalysis(phishing_keywords_found=0, detected_keywords=[])

    phishing_keywords = [
        # Urgency & fear
        "urgent",
        "immediately",
        "action required",
        "security alert",
        "suspended",
        "account locked",
        "unauthorized access",
        # Verification & credential harvesting
        "verify",
        "confirm",
        "login",
        "signin",
        "password",
        "reset",
        "update your account",
        "confirm your identity",
        # Financial
        "invoice",
        "payment",
        "refund",
        "wire transfer",
        "gift card",
        "bank transfer",
        "overdue payment",
        # Prize / social engineering
        "congratulations",
        "you have won",
        "lottery",
        "jackpot",
        "claim your prize",
        "free offer",
        "limited time",
        # Impersonation
        "dear customer",
        "dear user",
        "dear account holder",
    ]

    detected = [k for k in phishing_keywords if k in text]
    return ContentAnalysis(phishing_keywords_found=len(detected), detected_keywords=detected[:10])


# ============================================
# WHOIS API Domain Age Check (cached)
# ============================================
_domain_age_cache: Dict[str, dict] = {}
_DOMAIN_AGE_CACHE_TTL = 86400  # 24 hours


def _check_domain_age_sync(domain: str, api_key: str) -> Optional[dict]:
    """Check domain age via WHOIS XML API (whoisxmlapi.com) with caching."""
    cache_key = domain.lower()
    cached = _domain_age_cache.get(cache_key)
    if cached and (time.time() - cached.get("_ts", 0)) < _DOMAIN_AGE_CACHE_TTL:
        return cached

    try:
        import httpx as _httpx
        url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            "apiKey": api_key,
            "domainName": domain,
            "outputFormat": "JSON",
        }
        resp = _httpx.get(url, params=params, timeout=3.0)
        resp.raise_for_status()
        data = resp.json()

        whois_record = data.get("WhoisRecord", {})
        created_date_str = whois_record.get("createdDate") or whois_record.get("registryData", {}).get("createdDate")

        if not created_date_str:
            return None

        # Parse the ISO date
        created_date_str_clean = created_date_str.split("T")[0] if "T" in created_date_str else created_date_str[:10]
        from datetime import datetime as _dt
        try:
            created_dt = _dt.strptime(created_date_str_clean, "%Y-%m-%d")
        except ValueError:
            return None

        age_days = (datetime.now() - created_dt).days
        result = {
            "age_days": age_days,
            "created": created_date_str_clean,
            "is_new": age_days < 30,
            "_ts": time.time(),
        }
        _domain_age_cache[cache_key] = result
        logger.info(f"Domain age for {domain}: {age_days} days (created {created_date_str_clean})")
        return result

    except Exception as e:
        logger.warning(f"WHOIS API lookup failed for {domain}: {e}")
        return None


# ============================================
# Google Safe Browsing API v4
# ============================================
_safe_browsing_cache: Dict[str, dict] = {}
_SB_CACHE_TTL = 3600  # 1 hour


async def check_google_safe_browsing(urls: List[str], api_key: Optional[str] = None) -> Dict[str, List[str]]:
    """
    Check URLs against Google Safe Browsing API v4.
    Returns dict mapping each flagged URL to its threat types.
    """
    key = api_key or os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    if not key or not urls:
        return {}

    # Deduplicate and filter
    unique_urls = list(dict.fromkeys(u for u in urls if isinstance(u, str) and u))
    if not unique_urls:
        return {}

    # Check cache first
    threats: Dict[str, List[str]] = {}
    uncached_urls = []
    for u in unique_urls:
        cache_key = hashlib.md5(u.encode()).hexdigest()
        cached = _safe_browsing_cache.get(cache_key)
        if cached and (time.time() - cached.get("_ts", 0)) < _SB_CACHE_TTL:
            if cached.get("threats"):
                threats[u] = cached["threats"]
        else:
            uncached_urls.append(u)

    if not uncached_urls:
        return threats

    # Build Safe Browsing API request
    sb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    threat_entries = [{"url": u} for u in uncached_urls[:500]]  # API limit
    payload = {
        "client": {"clientId": "webshield", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": threat_entries,
        },
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(sb_url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        # Parse matches
        for match in data.get("matches", []):
            matched_url = match.get("threat", {}).get("url", "")
            threat_type = match.get("threatType", "UNKNOWN")
            if matched_url:
                threats.setdefault(matched_url, []).append(threat_type)

        # Cache all results (including clean URLs)
        for u in uncached_urls:
            cache_key = hashlib.md5(u.encode()).hexdigest()
            _safe_browsing_cache[cache_key] = {
                "threats": threats.get(u, []),
                "_ts": time.time(),
            }

        if threats:
            logger.warning(f"Google Safe Browsing flagged {len(threats)} URLs: {list(threats.keys())[:3]}")
        else:
            logger.info(f"Google Safe Browsing: {len(uncached_urls)} URLs clean")

    except Exception as e:
        logger.warning(f"Google Safe Browsing API error: {e}")

    return threats


# ============================================
# URL Redirect Chain Resolution
# ============================================
async def resolve_redirect_chain(url: str, max_redirects: int = 5) -> List[str]:
    """
    Follow HTTP redirects and return the chain of URLs.
    Returns list starting with the original URL and ending at final destination.
    """
    chain = [url]
    current = url
    try:
        async with httpx.AsyncClient(
            timeout=3.0,
            follow_redirects=False,
            verify=False,
        ) as client:
            for _ in range(max_redirects):
                try:
                    resp = await client.head(current, follow_redirects=False)
                except httpx.RequestError:
                    # Try GET as fallback (some servers don't support HEAD)
                    try:
                        resp = await client.get(current, follow_redirects=False)
                    except httpx.RequestError:
                        break

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if not location:
                        break
                    # Handle relative URLs
                    if location.startswith("/"):
                        parsed = urlparse(current)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    chain.append(location)
                    current = location
                else:
                    break  # No more redirects
    except Exception as e:
        logger.warning(f"Redirect chain resolution failed for {url}: {e}")

    return chain


async def resolve_redirect_chains_batch(urls: List[str]) -> Dict[str, List[str]]:
    """Resolve redirect chains for multiple URLs concurrently."""
    if not urls:
        return {}

    enable_redirect = os.getenv("ENABLE_REDIRECT_RESOLUTION", "true").lower() == "true"
    if not enable_redirect:
        return {}

    # Only resolve shortened/suspicious URLs to save time
    shortener_domains = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "tiny.cc", "lnkd.in", "cutt.ly", "rb.gy",
        "shorturl.at", "j.mp", "v.gd",
    }

    urls_to_resolve = []
    for u in urls:
        try:
            parsed = urlparse(u)
            if parsed.netloc.lower().replace("www.", "") in shortener_domains:
                urls_to_resolve.append(u)
        except Exception:
            pass

    if not urls_to_resolve:
        return {}

    semaphore = asyncio.Semaphore(4)
    results: Dict[str, List[str]] = {}

    async def _resolve_one(url: str):
        async with semaphore:
            chain = await resolve_redirect_chain(url)
            if len(chain) > 1:  # Only store if there were actual redirects
                results[url] = chain

    tasks = [asyncio.create_task(_resolve_one(u)) for u in urls_to_resolve[:5]]
    try:
        await asyncio.wait(tasks, timeout=3.0)
    except Exception:
        pass

    return results


# ============================================
# NLP Phishing Pattern Detection
# ============================================
def analyze_phishing_patterns_nlp(
    subject: Optional[str] = None,
    body_snippet: Optional[str] = None,
    sender_email: Optional[str] = None,
    sender_name: Optional[str] = None,
) -> Tuple[int, List[NlpPatternResult], float]:
    """
    Multi-signal NLP phishing pattern detection with compound scoring.
    Returns (nlp_score 0-100, patterns list, confidence 0.0-1.0).
    """
    enable_nlp = os.getenv("ENABLE_NLP_ANALYSIS", "true").lower() == "true"
    if not enable_nlp:
        return 0, [], 0.0

    text = " ".join(filter(None, [subject, body_snippet, sender_name])).lower()
    if not text or len(text) < 5:
        return 0, [], 0.0

    patterns: List[NlpPatternResult] = []
    score = 0

    # --- Pattern 1: Urgency Escalation ---
    urgency_phrases = [
        (r"\b(urgent|immediately|right now|asap|within \d+ hours?)\b", "high"),
        (r"\b(act now|don'?t delay|limited time|expires? (today|soon|tomorrow))\b", "high"),
        (r"\b(final (notice|warning|reminder)|last chance|before it'?s too late)\b", "critical"),
        (r"\b(time.?sensitive|critical update|immediate action)\b", "high"),
    ]
    for pattern, severity in urgency_phrases:
        match = re.search(pattern, text)
        if match:
            patterns.append(NlpPatternResult(
                pattern_type="urgency_escalation",
                description=f"Urgency language detected: '{match.group()}'",
                severity=severity,
                confidence=0.85,
                matched_text=match.group(),
            ))
            score += 18 if severity == "critical" else 12

    # --- Pattern 2: Authority Impersonation ---
    authority_phrases = [
        (r"\b(security team|it department|system administrator|compliance officer)\b", "high"),
        (r"\b(ceo|cfo|cto|managing director|board of directors)\b", "medium"),
        (r"\b(official notice|legal action|law enforcement|court order)\b", "critical"),
        (r"\b(internal audit|security review|policy violation)\b", "medium"),
    ]
    for pattern, severity in authority_phrases:
        match = re.search(pattern, text)
        if match:
            patterns.append(NlpPatternResult(
                pattern_type="authority_impersonation",
                description=f"Authority impersonation detected: '{match.group()}'",
                severity=severity,
                confidence=0.80,
                matched_text=match.group(),
            ))
            score += 15 if severity == "critical" else 10

    # --- Pattern 3: Credential Harvesting ---
    cred_phrases = [
        (r"\b(verify your (account|identity|password|email))\b", "critical"),
        (r"\b(confirm your (credentials|login|information))\b", "critical"),
        (r"\b(update your (password|payment|billing|account))\b", "high"),
        (r"\b(re-?enter your (password|pin|ssn|social security))\b", "critical"),
        (r"\b(click (here|below|the link) to (verify|confirm|update|login|sign.?in))\b", "critical"),
    ]
    for pattern, severity in cred_phrases:
        match = re.search(pattern, text)
        if match:
            patterns.append(NlpPatternResult(
                pattern_type="credential_harvesting",
                description=f"Credential request detected: '{match.group()}'",
                severity=severity,
                confidence=0.90,
                matched_text=match.group(),
            ))
            score += 20 if severity == "critical" else 12

    # --- Pattern 4: Emotional Manipulation ---
    emotional_phrases = [
        (r"\b(congratulations|you('ve| have) (been selected|won))\b", "high"),
        (r"\b(your account (has been|will be) (suspended|closed|terminated|locked))\b", "critical"),
        (r"\b(unusual (activity|login|sign.?in)|unauthorized (access|transaction))\b", "high"),
        (r"\b(failure to (comply|respond|verify) will result in)\b", "critical"),
    ]
    for pattern, severity in emotional_phrases:
        match = re.search(pattern, text)
        if match:
            patterns.append(NlpPatternResult(
                pattern_type="emotional_manipulation",
                description=f"Emotional manipulation detected: '{match.group()}'",
                severity=severity,
                confidence=0.82,
                matched_text=match.group(),
            ))
            score += 15 if severity == "critical" else 10

    # --- Pattern 5: Information Harvesting ---
    info_phrases = [
        (r"\b(social security|ssn|tax.?id|national.?id)\b", "critical"),
        (r"\b(credit card|bank account|routing number|swift code)\b", "critical"),
        (r"\b(date of birth|mother'?s maiden|security question)\b", "high"),
        (r"\b(send (us|me) your (details|information|documents))\b", "high"),
    ]
    for pattern, severity in info_phrases:
        match = re.search(pattern, text)
        if match:
            patterns.append(NlpPatternResult(
                pattern_type="information_harvesting",
                description=f"Information harvesting detected: '{match.group()}'",
                severity=severity,
                confidence=0.88,
                matched_text=match.group(),
            ))
            score += 20 if severity == "critical" else 12

    # --- Compound scoring: multiple patterns compound the threat ---
    unique_pattern_types = set(p.pattern_type for p in patterns)
    if len(unique_pattern_types) >= 3:
        score += 15  # Multiple attack vectors = high threat
        # Add compound pattern
        patterns.append(NlpPatternResult(
            pattern_type="compound_threat",
            description=f"Multiple attack vectors detected: {', '.join(unique_pattern_types)}",
            severity="critical",
            confidence=0.92,
            matched_text="",
        ))
    elif len(unique_pattern_types) >= 2:
        score += 8

    # Specific dangerous combos
    if "credential_harvesting" in unique_pattern_types and "urgency_escalation" in unique_pattern_types:
        score += 10  # Classic phishing combo

    # Cap score
    score = min(100, max(0, score))

    # Calculate confidence based on number and quality of patterns
    if patterns:
        avg_confidence = sum(p.confidence for p in patterns) / len(patterns)
        confidence = min(0.98, avg_confidence + (len(patterns) * 0.02))
    else:
        confidence = 0.0

    return score, patterns, confidence


# ============================================
# AI Threat Explanation via Groq LLM
# ============================================
async def generate_threat_explanation(
    threat_score: int,
    threat_level: str,
    summary: str,
    reasons: List[str],
    sender_email: str,
    details: dict,
) -> Optional[ThreatExplanation]:
    """Generate AI-powered natural language threat explanation using Groq LLM."""
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    groq_model = os.getenv("GROQ_EXPLANATION_MODEL", "llama-3.1-8b-instant")
    if not groq_key:
        return None

    # Build context for the LLM
    sender_rep = details.get("sender_reputation", {})
    header_info = details.get("header_analysis", {})
    link_info = details.get("link_analysis", {})
    content_info = details.get("content_analysis", {})

    prompt = f"""You are a cybersecurity analyst explaining email threat scan results to a non-technical user.

Email scan results:
- Sender: {sender_email}
- Threat Score: {threat_score}/100 (higher = more dangerous)
- Threat Level: {threat_level}
- Summary: {summary}
- Reasons: {json.dumps(reasons)}
- Sender domain: {sender_rep.get("domain", "unknown")}
- Trusted domain: {sender_rep.get("is_trusted_domain", False)}
- Domain age: {sender_rep.get("domain_age_days", "unknown")} days
- SPF: {header_info.get("spf_status", "unknown")}, DKIM: {header_info.get("dkim_status", "unknown")}, DMARC: {header_info.get("dmarc_status", "unknown")}
- Links found: {link_info.get("link_count", 0)}, Suspicious: {len(link_info.get("suspicious_links", []))}, Malicious: {len(link_info.get("malicious_links", []))}
- Phishing keywords: {content_info.get("phishing_keywords_found", 0)}
- NLP score: {content_info.get("nlp_score", 0)}

Respond ONLY with valid JSON in this exact format:
{{
  "why_marked": "2-3 sentences explaining why this email received its threat level in plain English",
  "factor_breakdown": [
    {{"factor": "Sender Reputation", "score": 0-100, "weight": "40%", "summary": "brief explanation"}},
    {{"factor": "Email Authentication", "score": 0-100, "weight": "30%", "summary": "brief explanation"}},
    {{"factor": "Link Safety", "score": 0-100, "weight": "30%", "summary": "brief explanation"}},
    {{"factor": "Content Analysis", "score": 0-100, "weight": "bonus", "summary": "brief explanation"}}
  ],
  "confidence_explanation": "1 sentence about how confident we are in this assessment",
  "recommendations": ["actionable recommendation 1", "actionable recommendation 2", "actionable recommendation 3"]
}}"""

    try:
        groq_timeout = float(os.getenv("GROQ_REQUEST_TIMEOUT_SECONDS", "5.0"))
        async with httpx.AsyncClient(timeout=groq_timeout) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {groq_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": groq_model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 600,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            data = resp.json()

        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not content:
            return None

        parsed = json.loads(content)
        return ThreatExplanation(
            why_marked=parsed.get("why_marked", ""),
            factor_breakdown=parsed.get("factor_breakdown", []),
            confidence_explanation=parsed.get("confidence_explanation", ""),
            recommendations=parsed.get("recommendations", []),
        )

    except Exception as e:
        logger.warning(f"Groq AI explanation failed: {e}")
        return None


async def analyze_headers(
    headers: Optional[EmailHeaders],
    sender_email: Optional[str] = None,
    allow_live_dns: bool = True,
    cache_only: bool = False,
) -> HeaderAnalysis:
    """
    Analyze email authentication using real DNS lookups for SPF/DMARC/DKIM.

    If sender_email is provided and auth_checker is available, performs real
    DNS lookups. Otherwise falls back to headers provided by the client.
    """

    domain = _extract_sender_domain(sender_email or "")
    cached = _get_cached_auth(domain)

    if cached and isinstance(cached, dict):
        try:
            return HeaderAnalysis(**cached)
        except Exception:
            pass

    # Try real DNS-based authentication check first
    if (not cache_only) and allow_live_dns and AUTH_CHECKER_AVAILABLE and sender_email:
        try:
            logger.info(f"Performing real DNS auth check for: {sender_email}")
            auth_result = await asyncio.wait_for(check_email_authentication_async(sender_email), timeout=3.0)

            spf_posture = "configured" if auth_result.spf.record else "missing"
            if auth_result.spf.record and auth_result.spf.all_mechanism in ("+all", "?all"):
                spf_posture = "weak"

            dkim_posture = "configured" if auth_result.dkim.has_dkim_record else "missing"

            dmarc_posture = "missing"
            if auth_result.dmarc.record:
                dmarc_posture = auth_result.dmarc.policy or "configured"

            logger.info(
                f"DNS Auth posture - SPF: {spf_posture}, DKIM: {dkim_posture}, DMARC: {dmarc_posture}, Score: {auth_result.overall_score}"
            )

            client_spf = str((headers.spf if headers else None) or "unknown").lower()
            client_dkim = str((headers.dkim if headers else None) or "unknown").lower()
            client_dmarc = str((headers.dmarc if headers else None) or "unknown").lower()

            # If client headers are unknown, derive status from DNS posture
            final_spf = client_spf
            final_dkim = client_dkim
            final_dmarc = client_dmarc
            if client_spf == "unknown":
                final_spf = "pass" if spf_posture == "configured" else ("neutral" if spf_posture == "weak" else "none")
            if client_dkim == "unknown":
                final_dkim = "pass" if dkim_posture == "configured" else "none"
            if client_dmarc == "unknown":
                final_dmarc = "pass" if dmarc_posture in ("reject", "quarantine", "configured") else "none"

            # IMPORTANT: Use DNS-derived status for authentication check
            msg_is_authenticated = (final_spf == "pass" or final_dkim == "pass") and final_dmarc != "fail"

            # Calculate score based on final status values
            msg_score = 0
            if final_spf == "pass":
                msg_score += 33
            elif final_spf == "fail":
                msg_score -= 20
            if final_dkim == "pass":
                msg_score += 33
            elif final_dkim == "fail":
                msg_score -= 20
            if final_dmarc == "pass":
                msg_score += 34
            elif final_dmarc == "fail":
                msg_score -= 20
            msg_score = max(0, min(100, msg_score))

            blended_score = msg_score if (final_spf, final_dkim, final_dmarc) != ("unknown", "unknown", "unknown") else auth_result.overall_score

            ha = HeaderAnalysis(
                spf_status=final_spf,
                dkim_status=final_dkim,
                dmarc_status=final_dmarc,
                spf_posture=spf_posture,
                dkim_posture=dkim_posture,
                dmarc_posture=dmarc_posture,
                is_authenticated=bool(msg_is_authenticated),
                authentication_score=int(blended_score or 0),
                reply_to=(headers.reply_to if headers else None),
                return_path=(headers.return_path if headers else None),
                received=list(headers.received or []) if headers and headers.received else [],
                authentication_results=(headers.authentication_results if headers else None),
            )

            try:
                _set_cached_auth(domain, ha.model_dump() if hasattr(ha, "model_dump") else ha.dict())
            except Exception:
                pass

            return ha

        except Exception as e:
            logger.warning(f"DNS auth check failed, falling back to header analysis: {e}")

    # Fallback to client-provided headers
    if not headers:
        # With no message headers, we do NOT claim authentication.
        # Keep a neutral score so UI doesn't show an explicit fail.
        return HeaderAnalysis(
            spf_status="unknown",
            dkim_status="unknown",
            dmarc_status="unknown",
            spf_posture="unknown",
            dkim_posture="unknown",
            dmarc_posture="unknown",
            is_authenticated=False,
            authentication_score=50,
            reply_to=None,
            return_path=None,
            received=[],
            authentication_results=None,
        )

    spf = (headers.spf or "unknown").lower()
    dkim = (headers.dkim or "unknown").lower()
    dmarc = (headers.dmarc or "unknown").lower()

    # Calculate authentication score
    auth_score = 0

    if spf == "pass":
        auth_score += 33
    elif spf == "fail":
        auth_score -= 20

    if dkim == "pass":
        auth_score += 33
    elif dkim == "fail":
        auth_score -= 20

    if dmarc == "pass":
        auth_score += 34
    elif dmarc == "fail":
        auth_score -= 20

    # Ensure score is in valid range
    auth_score = max(0, min(100, auth_score))

    is_authenticated = (spf == "pass" or dkim == "pass") and dmarc != "fail"

    return HeaderAnalysis(
        spf_status=spf,
        dkim_status=dkim,
        dmarc_status=dmarc,
        spf_posture="unknown",
        dkim_posture="unknown",
        dmarc_posture="unknown",
        is_authenticated=is_authenticated,
        authentication_score=auth_score,
        reply_to=headers.reply_to,
        return_path=headers.return_path,
        received=list(headers.received or []) if headers.received else [],
        authentication_results=headers.authentication_results,
    )


async def analyze_links_patterns(links: List[str], total_budget_seconds: float = 4.0) -> Dict[str, dict]:
    if not links:
        return {}

    unique_links: list[str] = []
    seen: set[str] = set()
    for l in links:
        if isinstance(l, str) and l and l not in seen:
            unique_links.append(l)
            seen.add(l)

    unique_links = unique_links[:10]
    if not unique_links:
        return {}

    semaphore = asyncio.Semaphore(8)
    results: Dict[str, dict] = {}

    async def _one(detector: WebShieldDetector, url: str):
        async with semaphore:
            try:
                r = await detector.analyze_url_patterns(url)
                if isinstance(r, dict):
                    results[url] = r
            except Exception:
                return

    try:
        detector = WebShieldDetector()
        tasks = [asyncio.create_task(_one(detector, u)) for u in unique_links]
        done, pending = await asyncio.wait(tasks, timeout=max(0.2, total_budget_seconds))
        for t in pending:
            t.cancel()
        await asyncio.gather(*done, return_exceptions=True)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
    except Exception:
        return results

    return results


def analyze_links(links: List[str]) -> LinkAnalysis:
    """Analyze links in email with comprehensive pattern detection"""
    suspicious_links = []
    malicious_links = []

    # URL shorteners - often used to hide malicious destinations
    url_shorteners = [
        r"bit\.ly",
        r"tinyurl\.com",
        r"goo\.gl",
        r"t\.co",
        r"is\.gd",
        r"buff\.ly",
        r"ow\.ly",
        r"adf\.ly",
        r"j\.mp",
        r"v\.gd",
        r"cutt\.ly",
        r"rb\.gy",
        r"shorturl\.at",
        r"tiny\.cc",
    ]

    # Suspicious patterns in URLs
    suspicious_patterns = [
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
        r"[a-z0-9]{25,}",  # Very long random strings (likely tracking/obfuscation)
        r"verify.*account",
        r"confirm.*identity",
        r"update.*payment",
        r"suspended.*account",
        r"unusual.*activity",
        r"secure.*login",
        r"password.*reset",
        r"account.*locked",
        r"urgent.*action",
        r"\.xyz\/",
        r"\.tk\/",
        r"\.ml\/",
        r"\.cf\/",
        r"\.gq\/",  # Free TLDs often used in phishing
        r"login.*\?",
        r"signin.*\?",
        r"auth.*\?",  # Login with query params
        r"@.*@",  # Multiple @ signs (obfuscation)
        r"[0-9]+\.[a-z]+\.[a-z]+\/",  # Subdomain with numbers
        r"\.php\?.*=",  # PHP with params (common in phishing)
        r"data:text\/html",  # Data URLs
        r"javascript:",  # JavaScript URLs
    ]

    # Known malicious patterns
    malicious_patterns = [
        r"phishing",
        r"malware",
        r"virus",
        r"trojan",
        r"ransomware",
        r"free.*money",
        r"click.*here.*win",
        r"congratulations.*won",
        r"nigerian.*prince",
        r"lottery.*winner",
        r"inheritance.*claim",
        r"wire.*transfer",
        r"western.*union",
        r"bitcoin.*payment",
        r"\.exe$",
        r"\.scr$",
        r"\.bat$",
        r"\.cmd$",
        r"\.ps1$",  # Executable extensions
        r"download.*invoice",
        r"download.*receipt",
        r"paypal.*verify",
        r"amazon.*verify",
        r"apple.*verify",
        r"microsoft.*verify",
        r"bank.*of.*america.*verify",
        r"wells.*fargo.*verify",
        r"password.*expire",
        r"account.*terminate",
    ]

    # Brand impersonation patterns
    brand_impersonation = [
        # Global brands
        (r"paypal", r"paypa[l1]|paypai|peypal|paypaI"),
        (r"apple", r"app[l1]e|app1e|appie"),
        (r"amazon", r"amaz[o0]n|arnazon|amazom"),
        (r"microsoft", r"micr[o0]soft|mircosoft|m1crosoft"),
        (r"netflix", r"netf[l1]ix|netfiix|netfl1x"),
        (r"google", r"g[o0][o0]gle|googie|g00gle"),
        # Indian bank impersonation
        (r"hdfc", r"hdf[c0]|hdtc|hd[f]+[c]+bank"),
        (r"icici", r"[i1]c[i1]c[i1]|1c1c1"),
        (r"sbi", r"sb[i1l]\.co|sb[i1l]bank"),
        (r"axisbank", r"ax[i1]sbank|axis[b8]ank"),
        (r"kotak", r"k[o0]tak|k0tak"),
    ]

    for link in links:
        link_lower = link.lower()
        is_malicious = False
        is_suspicious = False

        # Check for malicious patterns
        if any(re.search(pattern, link_lower) for pattern in malicious_patterns):
            is_malicious = True

        # Check for brand impersonation
        for brand, impersonation_pattern in brand_impersonation:
            if re.search(impersonation_pattern, link_lower) and brand not in link_lower:
                is_malicious = True
                break

        # Check for URL shorteners
        if any(re.search(pattern, link_lower) for pattern in url_shorteners):
            is_suspicious = True

        # Check for suspicious patterns
        if any(re.search(pattern, link_lower) for pattern in suspicious_patterns):
            is_suspicious = True

        # Check for domain spoofing (e.g., paypal.com.malicious.com)
        if re.search(r"\.(com|org|net|edu|gov)\.", link_lower):
            is_suspicious = True

        # Categorize
        if is_malicious:
            malicious_links.append(link)
        elif is_suspicious:
            suspicious_links.append(link)

    # Calculate risk score with weighted factors
    risk_score = 0

    # Many links is somewhat suspicious
    if len(links) > 15:
        risk_score += 25
    elif len(links) > 10:
        risk_score += 15
    elif len(links) > 5:
        risk_score += 5

    # Weight suspicious and malicious links
    risk_score += len(suspicious_links) * 12
    risk_score += len(malicious_links) * 35

    # Cap at 100
    risk_score = min(100, risk_score)

    return LinkAnalysis(
        links=links,
        suspicious_links=suspicious_links,
        malicious_links=malicious_links,
        vt_suspicious_links=[],
        vt_malicious_links=[],
        vt_scanned_links=0,
        vt_scan_timed_out=False,
        link_count=len(links),
        risk_score=risk_score,
    )


async def analyze_links_virustotal(
    links: List[str], total_budget_seconds: float = 5.0, api_key: Optional[str] = None
) -> tuple[list[str], list[str], int, bool]:
    if not links:
        return [], [], 0, False

    try:
        from .utils import WebShieldDetector
    except Exception:
        return [], [], 0, False

    unique_links = []
    seen = set()
    for l in links:
        if isinstance(l, str) and l and l not in seen:
            unique_links.append(l)
            seen.add(l)

    semaphore = asyncio.Semaphore(6)
    vt_suspicious: list[str] = []
    vt_malicious: list[str] = []

    completed_urls: set[str] = set()

    async def _scan_one(detector: WebShieldDetector, url: str):
        async with semaphore:
            vt = await detector.check_virustotal(url, api_key=api_key)
            completed_urls.add(url)
            if not isinstance(vt, dict):
                return
            mc = int(vt.get("malicious_count") or 0)
            sc = int(vt.get("suspicious_count") or 0)
            if mc > 0:
                vt_malicious.append(url)
            elif sc > 0:
                vt_suspicious.append(url)

    timed_out = False
    scanned_count = 0
    try:
        async with WebShieldDetector() as detector:
            tasks = [asyncio.create_task(_scan_one(detector, u)) for u in unique_links]
            try:
                done, pending = await asyncio.wait(tasks, timeout=max(0.1, total_budget_seconds))
                if pending:
                    timed_out = True
                    for t in pending:
                        t.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                await asyncio.gather(*done, return_exceptions=True)
            except Exception:
                timed_out = True
            finally:
                scanned_count = len(completed_urls)
    except Exception:
        return [], [], 0, False

    vt_suspicious = list(dict.fromkeys(vt_suspicious))
    vt_malicious = list(dict.fromkeys(vt_malicious))
    return vt_suspicious, vt_malicious, scanned_count, timed_out


async def analyze_attachment_hashes_virustotal(
    hashes: List[str], total_budget_seconds: float = 6.0, api_key: Optional[str] = None
) -> Dict[str, dict]:
    if not hashes:
        return {}

    unique_hashes: list[str] = []
    seen: set[str] = set()
    for h in hashes:
        if isinstance(h, str):
            s = h.strip().lower()
            if len(s) >= 64 and s not in seen:
                seen.add(s)
                unique_hashes.append(s)

    unique_hashes = unique_hashes[:10]
    if not unique_hashes:
        return {}

    semaphore = asyncio.Semaphore(6)
    results: Dict[str, dict] = {}

    async def _scan_one(detector: WebShieldDetector, sha256: str):
        async with semaphore:
            r = await detector.check_virustotal_file_hash(sha256, api_key=api_key)
            if isinstance(r, dict):
                results[sha256] = r

    try:
        async with WebShieldDetector() as detector:
            tasks = [asyncio.create_task(_scan_one(detector, h)) for h in unique_hashes]
            done, pending = await asyncio.wait(tasks, timeout=max(0.2, total_budget_seconds))
            for t in pending:
                t.cancel()
            await asyncio.gather(*done, return_exceptions=True)
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
    except Exception:
        return results

    return results


async def calculate_threat_score(
    sender_rep: SenderReputation, header_analysis: HeaderAnalysis, link_analysis: LinkAnalysis,
    content_analysis: Optional[ContentAnalysis] = None,
) -> tuple[int, str, str, List[str], float]:
    """Calculate overall threat score and assessment. Returns (score, level, summary, reasons, confidence)."""

    # Generate reasons first (needed for override logic)
    reasons = []

    # Weighted scoring
    # Sender reputation: 40% weight
    sender_score = sender_rep.reputation_score * 0.4

    # Header authentication: 30% weight
    auth_score = header_analysis.authentication_score * 0.3

    # Link analysis: 30% weight (inverted - lower risk is better)
    link_score = (100 - link_analysis.risk_score) * 0.3

    # Calculate base safety score (0-100, where 100 is safest)
    safety_score = sender_score + auth_score + link_score

    # IMPORTANT: Boost safety score for trusted domains with good reputation
    # This prevents false "suspicious" classifications for legitimate emails
    if sender_rep.is_trusted_domain and sender_rep.reputation_score >= 70:
        safety_score = max(safety_score, 70)  # Minimum 70 for trusted domains
    elif sender_rep.reputation_score >= 80 and header_analysis.is_authenticated:
        safety_score = max(safety_score, 65)

    # Track if we have actual suspicious patterns (not just missing data)
    has_suspicious_patterns = False
    pattern_flags = []

    # Check for actual red flags
    if link_analysis.malicious_links:
        has_suspicious_patterns = True
        pattern_flags.append(f"malicious_links:{len(link_analysis.malicious_links)}")

    if link_analysis.suspicious_links:
        has_suspicious_patterns = True
        pattern_flags.append(f"suspicious_links:{len(link_analysis.suspicious_links)}")

    if sender_rep.is_disposable:
        has_suspicious_patterns = True
        pattern_flags.append("disposable_email")

    if sender_rep.reputation_score < 30:
        has_suspicious_patterns = True
        pattern_flags.append("poor_reputation")

    # Check for explicit auth failure (not just unknown)
    has_explicit_auth_failure = (
        header_analysis.spf_status == "fail"
        or header_analysis.dkim_status == "fail"
        or header_analysis.dmarc_status == "fail"
    )

    is_auth_unknown = header_analysis.spf_status == "unknown" and header_analysis.dkim_status == "unknown"

    # === SMART SCORING LOGIC ===

    # Rule 1: Auth passes + many links (>5) = slight suspicion (but not dangerous)
    if header_analysis.is_authenticated and link_analysis.link_count > 5:
        if link_analysis.link_count > 15:
            safety_score -= 15  # Many links in authenticated email
            pattern_flags.append("many_links")
        elif link_analysis.link_count > 10:
            safety_score -= 10
        else:
            safety_score -= 5  # Just a note, not really suspicious

    # Rule 2: Auth fails = only suspicious if OTHER red flags exist
    if has_explicit_auth_failure:
        if has_suspicious_patterns:
            # Auth failed AND has other red flags = significant penalty
            safety_score = min(safety_score, 35)
            reasons.append("⚠️ Email authentication failed")
        elif not sender_rep.is_trusted_domain:
            # Auth failed but no other red flags = moderate penalty
            safety_score = min(safety_score, 50)
            reasons.append("⚠️ Email authentication could not be verified")
        # If trusted domain, auth failure might be config issue, minor penalty
        else:
            safety_score -= 10

    # Rule 3: Unknown auth = don't penalize unless other issues exist
    if is_auth_unknown and not sender_rep.is_trusted_domain:
        if has_suspicious_patterns:
            safety_score = min(safety_score, 45)
        # else: no penalty for unknown auth alone

    # Calculate final threat score
    threat_score = int(100 - safety_score)

    # Ensure score is in valid range
    threat_score = max(0, min(100, threat_score))

    # === SAFE BROWSING FIRST (authoritative, real-time) ===
    sb_threats = getattr(link_analysis, 'safe_browsing_threats', {})
    sb_any_flagged = len(sb_threats) > 0

    gmail_api_verified = getattr(header_analysis, 'gmail_api_verified', False)

    if sb_any_flagged:
        # Google Safe Browsing is authoritative — mark dangerous
        sb_count = len(sb_threats)
        threat_types = set()
        for types in sb_threats.values():
            threat_types.update(types)
        threat_level = "dangerous"
        threat_score = max(threat_score, 85)
        summary = f"Google Safe Browsing flagged {sb_count} malicious URL(s): {', '.join(threat_types)}"
        logger.warning(f"Safe Browsing flagged {sb_count} URLs — marking dangerous")
    else:

        if threat_score <= 33:
            threat_level = "safe"
            summary = "Email appears safe"
        elif threat_score <= 66:
            # Only mark suspicious if we have actual patterns
            if has_suspicious_patterns or has_explicit_auth_failure:
                threat_level = "suspicious"
                summary = "Email shows suspicious characteristics"
            else:
                # No real patterns, probably just unknown sender - call it safe
                threat_level = "safe"
                threat_score = min(threat_score, 33)  # Cap score
                summary = "Email appears safe"
        else:
            # High threat score - verify we have reasons
            if has_suspicious_patterns:
                threat_level = "dangerous"
                summary = "Email is likely dangerous"
            else:
                # High score but no clear patterns - downgrade to suspicious
                threat_level = "suspicious"
                threat_score = min(threat_score, 60)
                summary = "Email requires caution"

    # === BUILD REASONS LIST ===

    # Sender reputation reasons
    if sender_rep.is_trusted_domain:
        reasons.append("✓ Sender from trusted domain")
    elif sender_rep.reputation_score >= 70:
        reasons.append("✓ Sender has good reputation")
    elif sender_rep.reputation_score >= 40:
        reasons.append("Sender reputation is neutral")
    elif sender_rep.reputation_score >= 20:
        reasons.append("⚠️ Sender reputation is low")
    else:
        reasons.append("⚠️ Sender has poor reputation")

    # Authentication status reason
    if header_analysis.is_authenticated:
        reasons.append("✓ Domain email authentication records look valid (SPF/DKIM/DMARC)")
    elif has_explicit_auth_failure:
        # Already added above if applicable
        if "authentication" not in " ".join(reasons).lower():
            reasons.append("⚠️ Email authentication failed")
    elif is_auth_unknown:
        reasons.append("Email authentication status unknown")
    else:
        reasons.append("Authentication partially verified")

    # Link analysis reasons
    # (VirusTotal removed — using Safe Browsing + pattern analysis instead)

    if link_analysis.malicious_links:
        reasons.append(f"⚠️ Contains {len(link_analysis.malicious_links)} potentially dangerous link(s)")
    elif link_analysis.suspicious_links:
        reasons.append(f"⚠️ Contains {len(link_analysis.suspicious_links)} suspicious link(s)")
    elif link_analysis.link_count == 0:
        reasons.append("✓ No links found in email")
    elif link_analysis.link_count > 10:
        reasons.append(f"Contains {link_analysis.link_count} links")
    else:
        reasons.append("✓ All links appear safe")

    # Additional warnings
    if sender_rep.is_disposable:
        reasons.append("⚠️ Sender uses disposable email address")

    # Domain age warnings
    if sender_rep.is_newly_registered:
        reasons.append(f"⚠️ Domain registered < 30 days ago")
        threat_score = max(threat_score, 40)  # Newly registered domain is suspicious
    elif sender_rep.domain_age_days is not None and sender_rep.domain_age_days < 90:
        reasons.append(f"⚠️ Domain is only {sender_rep.domain_age_days} days old")

    # Google Safe Browsing reasons (scoring handled in primary threat level logic above)
    if sb_any_flagged:
        sb_count = len(sb_threats)
        sb_types = set()
        for types in sb_threats.values():
            sb_types.update(types)
        reasons.append(f"🛡️ Google Safe Browsing flagged {sb_count} URL(s): {', '.join(sb_types)}")

    # NLP pattern reasons
    if content_analysis and content_analysis.nlp_score > 0:
        nlp_score = content_analysis.nlp_score
        if nlp_score >= 50:
            reasons.append(f"⚠️ High phishing pattern score: {nlp_score}/100")
            threat_score = max(threat_score, 55)
            if threat_level == "safe":
                threat_level = "suspicious"
                summary = "Email shows strong phishing patterns"
        elif nlp_score >= 25:
            reasons.append(f"⚠️ Moderate phishing patterns detected (score: {nlp_score})")
        # Show top NLP patterns
        for pat in (content_analysis.nlp_patterns or [])[:2]:
            if pat.severity in ("critical", "high"):
                reasons.append(f"  → {pat.description}")

    # Redirect chain warnings
    redirects = getattr(link_analysis, 'redirect_chains', {})
    if redirects:
        reasons.append(f"⚠️ {len(redirects)} shortened URL(s) resolved with redirect chains")

    # Calculate confidence
    confidence = 0.85  # Base confidence
    if header_analysis.gmail_api_verified:
        confidence += 0.05
    if content_analysis and content_analysis.nlp_confidence > 0:
        confidence = (confidence + content_analysis.nlp_confidence) / 2
    if sb_threats:
        confidence = min(0.98, confidence + 0.05)
    confidence = round(min(0.98, max(0.50, confidence)), 2)

    # Ensure we have at least 3 reasons
    while len(reasons) < 3:
        reasons.append("✓ Scan completed successfully")

    return threat_score, threat_level, summary, reasons[:8], confidence  # Max 8 reasons


# API Endpoints
async def run_scan_logic(request: EmailScanRequest) -> EmailScanResponse:
    """
    Scan email metadata for threats

    This endpoint analyzes email metadata including sender reputation,
    authentication headers, and links to determine if an email is safe.
    """
    t0 = time.monotonic()
    total_budget_s = 4.8
    sender_email = str(request.email_metadata.sender_email)
    scan_type = _normalize_scan_type(request.scan_type)

    logger.info(f"Scanning email from {sender_email} (scan_type={scan_type})")

    gmail_api_auth = request.email_metadata.gmail_api_auth
    provided_headers = request.email_metadata.headers

    if gmail_api_auth:
        gapi_spf = (gmail_api_auth.spf or None)
        gapi_dkim = (gmail_api_auth.dkim or None)
        gapi_dmarc = (gmail_api_auth.dmarc or None)
        logger.info(f"Gmail API auth data received: SPF={gapi_spf}, DKIM={gapi_dkim}, DMARC={gapi_dmarc}")
        enhanced_headers = EmailHeaders(
            spf=gapi_spf or (provided_headers.spf if provided_headers else None),
            dkim=gapi_dkim or (provided_headers.dkim if provided_headers else None),
            dmarc=gapi_dmarc or (provided_headers.dmarc if provided_headers else None),
            via=provided_headers.via if provided_headers else None,
            reply_to=provided_headers.reply_to if provided_headers else None,
            return_path=provided_headers.return_path if provided_headers else None,
            received=provided_headers.received if provided_headers else None,
            authentication_results=provided_headers.authentication_results if provided_headers else None,
        )
    else:
        enhanced_headers = provided_headers

    links_limited = _dedupe_and_limit_links(request.email_metadata.links, limit=10)

    sender_rep = analyze_sender_reputation(sender_email, request.email_metadata.sender_name)

    header_analysis = HeaderAnalysis(
        spf_status="unknown",
        dkim_status="unknown",
        dmarc_status="unknown",
        spf_posture="unknown",
        dkim_posture="unknown",
        dmarc_posture="unknown",
        is_authenticated=False,
        authentication_score=50,
        reply_to=(enhanced_headers.reply_to if enhanced_headers else None),
        return_path=(enhanced_headers.return_path if enhanced_headers else None),
        received=list(enhanced_headers.received or []) if enhanced_headers and enhanced_headers.received else [],
        authentication_results=(enhanced_headers.authentication_results if enhanced_headers else None),
    )
    link_analysis = analyze_links(links_limited)
    content_analysis = analyze_content(request.email_metadata.subject)
    ai_explanation = None

    try:
        async with asyncio.timeout(total_budget_s):
            allow_dns = True  # Always enable DNS auth checks
            cache_only = False  # Always perform live DNS checks

            header_task = asyncio.create_task(
                analyze_headers(enhanced_headers, sender_email=sender_email, allow_live_dns=allow_dns, cache_only=cache_only)
            )

            pattern_budget = float(os.getenv("EMAIL_URL_PATTERN_BUDGET_SECONDS", "1.5"))
            pattern_task = asyncio.create_task(analyze_links_patterns(links_limited, total_budget_seconds=max(0.2, min(2.0, pattern_budget))))

            nlp_task = asyncio.create_task(
                asyncio.to_thread(
                    analyze_phishing_patterns_nlp,
                    subject=request.email_metadata.subject,
                    body_snippet=(getattr(request.email_metadata, "body_text", None) or "")[:500],
                    sender_email=sender_email,
                    sender_name=request.email_metadata.sender_name,
                )
            )

            try:
                header_analysis = await header_task
            except Exception as e:
                logger.warning(f"Header analysis failed (non-critical): {e}")

            if gmail_api_auth:
                gapi_spf = (gmail_api_auth.spf or None)
                gapi_dkim = (gmail_api_auth.dkim or None)
                gapi_dmarc = (gmail_api_auth.dmarc or None)
                if gapi_spf and gapi_spf != "unknown":
                    header_analysis.spf_status = gapi_spf
                if gapi_dkim and gapi_dkim != "unknown":
                    header_analysis.dkim_status = gapi_dkim
                if gapi_dmarc and gapi_dmarc != "unknown":
                    header_analysis.dmarc_status = gapi_dmarc

                auth_score = 0
                if header_analysis.spf_status == "pass":
                    auth_score += 33
                elif header_analysis.spf_status == "fail":
                    auth_score -= 20
                if header_analysis.dkim_status == "pass":
                    auth_score += 33
                elif header_analysis.dkim_status == "fail":
                    auth_score -= 20
                if header_analysis.dmarc_status == "pass":
                    auth_score += 34
                elif header_analysis.dmarc_status == "fail":
                    auth_score -= 20
                header_analysis.authentication_score = max(0, min(100, auth_score))
                header_analysis.is_authenticated = (
                    header_analysis.spf_status == "pass" or header_analysis.dkim_status == "pass"
                ) and header_analysis.dmarc_status != "fail"
                header_analysis.gmail_api_verified = True

            try:
                nlp_score, nlp_patterns, nlp_confidence = await nlp_task
                content_analysis.nlp_score = int(nlp_score or 0)
                content_analysis.nlp_patterns = nlp_patterns or []
                content_analysis.nlp_confidence = float(nlp_confidence or 0.0)
            except Exception as e:
                logger.warning(f"NLP analysis failed (non-critical): {e}")

            link_scan_results: Dict[str, dict] = {}
            try:
                link_scan_results = await pattern_task
            except Exception as e:
                logger.warning(f"Link pattern analysis failed (non-critical): {e}")

            if isinstance(link_scan_results, dict):
                link_analysis.link_scan_results = link_scan_results

                for u, r in link_scan_results.items():
                    if not u or not isinstance(r, dict):
                        continue
                    score = int(r.get("suspicious_score") or 0)
                    issues = r.get("detected_issues") or []
                    issues_text = " ".join([str(x) for x in issues])
                    if score >= 60:
                        if u not in link_analysis.suspicious_links and u not in link_analysis.malicious_links:
                            link_analysis.suspicious_links.append(u)
                    if "homograph" in issues_text.lower() or "punycode" in issues_text.lower() or "typosquat" in issues_text.lower() or "imperson" in issues_text.lower():
                        if u not in link_analysis.suspicious_links and u not in link_analysis.malicious_links:
                            link_analysis.suspicious_links.append(u)

                link_analysis.suspicious_links = list(dict.fromkeys(link_analysis.suspicious_links))

                pattern_scores = [int(v.get("suspicious_score") or 0) for v in link_scan_results.values() if isinstance(v, dict)]
                if pattern_scores:
                    heuristic_score = int(link_analysis.risk_score or 0)
                    pattern_score = int(max(pattern_scores) or 0)
                    link_analysis.risk_score = int((heuristic_score * 0.6) + (pattern_score * 0.4))

            if scan_type == "full":
                remaining = max(0.0, total_budget_s - (time.monotonic() - t0))

                sb_task = None
                redirect_task = None
                vt_task = None
                whois_task = None

                if remaining > 0.2:
                    sb_task = asyncio.create_task(asyncio.wait_for(check_google_safe_browsing(links_limited), timeout=min(3.0, remaining)))

                if remaining > 0.2:
                    redirect_task = asyncio.create_task(
                        asyncio.wait_for(resolve_redirect_chains_batch(links_limited[:5]), timeout=min(3.0, remaining))
                    )

                whois_api_key = os.getenv("WHOIS_API_KEY", "").strip()
                enable_age_check = os.getenv("ENABLE_DOMAIN_AGE_CHECK", "true").lower() == "true"
                if remaining > 0.2 and enable_age_check and whois_api_key and (not sender_rep.is_trusted_domain) and (not sender_rep.is_free_provider):
                    domain = sender_rep.domain
                    whois_task = asyncio.create_task(
                        asyncio.wait_for(asyncio.to_thread(_check_domain_age_sync, domain, whois_api_key), timeout=min(3.0, remaining))
                    )

                vt_key = os.getenv("VT_API_KEY", "").strip() or None
                if remaining > 0.2:
                    vt_task = asyncio.create_task(
                        analyze_links_virustotal(links_limited[:5], total_budget_seconds=min(3.0, remaining), api_key=vt_key)
                    )

                if sb_task:
                    try:
                        link_analysis.safe_browsing_threats = await sb_task
                    except Exception as e:
                        logger.warning(f"Safe Browsing failed (non-critical): {e}")

                if redirect_task:
                    try:
                        link_analysis.redirect_chains = await redirect_task
                    except Exception as e:
                        logger.warning(f"Redirect resolution failed (non-critical): {e}")

                if whois_task:
                    try:
                        age_result = await whois_task
                        if isinstance(age_result, dict):
                            sender_rep.domain_age_days = age_result.get("age_days")
                            sender_rep.domain_created = age_result.get("created")
                            sender_rep.is_newly_registered = bool(age_result.get("is_new", False))
                            try:
                                if sender_rep.is_newly_registered:
                                    sender_rep.reputation_score = max(0, int(sender_rep.reputation_score) - 20)
                                elif sender_rep.domain_age_days is not None and int(sender_rep.domain_age_days) < 90:
                                    sender_rep.reputation_score = max(0, int(sender_rep.reputation_score) - 10)
                                sender_rep.reputation_score = max(0, min(100, int(sender_rep.reputation_score)))
                            except Exception:
                                pass
                    except Exception as e:
                        logger.warning(f"WHOIS enrichment failed (non-critical): {e}")

                if vt_task:
                    try:
                        vt_suspicious, vt_malicious, scanned_count, timed_out = await asyncio.wait_for(vt_task, timeout=min(3.0, max(0.2, remaining)))
                        link_analysis.vt_suspicious_links = vt_suspicious
                        link_analysis.vt_malicious_links = vt_malicious
                        link_analysis.vt_scanned_links = int(scanned_count or 0)
                        link_analysis.vt_scan_timed_out = bool(timed_out)
                    except Exception as e:
                        logger.warning(f"VirusTotal enrichment failed (non-critical): {e}")

            threat_score, threat_level, summary, reasons, confidence = await calculate_threat_score(
                sender_rep, header_analysis, link_analysis, content_analysis
            )

            details_dict = {
                "sender_reputation": sender_rep.model_dump() if hasattr(sender_rep, "model_dump") else sender_rep.dict(),
                "header_analysis": header_analysis.model_dump() if hasattr(header_analysis, "model_dump") else header_analysis.dict(),
                "link_analysis": link_analysis.model_dump() if hasattr(link_analysis, "model_dump") else link_analysis.dict(),
                "content_analysis": content_analysis.model_dump() if hasattr(content_analysis, "model_dump") else content_analysis.dict(),
            }

            groq_key = os.getenv("GROQ_API_KEY", "").strip()
            if not groq_key:
                logger.info({
                    "event": "ai_explanation_skipped",
                    "reason": "missing_groq_api_key",
                })

            try:
                ai_explanation = await asyncio.wait_for(
                    generate_threat_explanation(
                        threat_score=threat_score,
                        threat_level=threat_level,
                        summary=summary,
                        reasons=reasons,
                        sender_email=sender_email,
                        details=details_dict,
                    ),
                    timeout=2.0,
                )
            except Exception:
                ai_explanation = None

            if ai_explanation is None and groq_key:
                logger.info({
                    "event": "ai_explanation_unavailable",
                    "reason": "timeout_or_error_or_empty",
                })

            response = EmailScanResponse(
                threat_score=threat_score,
                threat_level=threat_level,
                summary=summary,
                reasons=reasons,
                confidence=confidence,
                details=EmailScanDetails(
                    sender_reputation=sender_rep,
                    header_analysis=header_analysis,
                    link_analysis=link_analysis,
                    content_analysis=content_analysis,
                    attachments=[dict(a) for a in (request.email_metadata.attachments or []) if isinstance(a, dict)],
                    has_dangerous_attachments=bool(request.email_metadata.has_dangerous_attachments),
                ),
                ai_explanation=ai_explanation,
                scanned_at=datetime.now(),
            )

            duration_s = round((time.monotonic() - t0), 3)
            logger.info({
                "event": "scan_completed",
                "duration_seconds": duration_s,
                "scan_type": scan_type,
                "sender_email": sender_email,
                "threat_score": threat_score,
                "threat_level": threat_level,
            })

            return response

    except Exception as e:
        duration_s = round((time.monotonic() - t0), 3)
        logger.error({
            "event": "scan_logic_exception",
            "duration_seconds": duration_s,
            "scan_type": scan_type,
            "sender_email": sender_email,
            "error": str(e),
        }, exc_info=True)
        raise


@email_router.post("/scan-metadata", response_model=EmailScanResponse)
async def scan_email_metadata(request: EmailScanRequest):
    start = time.perf_counter()

    try:
        try:
            async with asyncio.timeout(5.0):
                response = await run_scan_logic(request)
        except asyncio.TimeoutError:
            logger.warning("Global scan timeout — returning partial result")

            details = _build_minimal_details()
            response = EmailScanResponse(
                threat_score=50,
                threat_level="suspicious",
                summary="Scan timed out — partial results shown",
                reasons=[
                    "Scan exceeded time limit",
                    "Some checks were skipped",
                    "Partial results returned",
                ],
                confidence=0.6,
                details=details,
                ai_explanation=None,
                scanned_at=datetime.now(),
            )

        duration = time.perf_counter() - start
        logger.info(f"Scan completed in {duration:.2f}s")
        return response

    except Exception:
        logger.exception("Unexpected scan failure")
        details = _build_minimal_details()
        return EmailScanResponse(
            threat_score=0,
            threat_level="unknown",
            summary="Scan failed",
            reasons=["Unexpected error occurred", "Partial results returned", "Try again"],
            confidence=0.0,
            details=details,
            ai_explanation=None,
            scanned_at=datetime.now(),
        )


@email_router.get("/check-auth")
async def check_email_auth(email: str):
    """
    Check email authentication records (SPF, DMARC, DKIM) for a sender.

    This endpoint performs real DNS lookups to verify the sender's domain
    has proper email authentication configured.

    Query Parameters:
        email: The sender's email address (e.g., user@example.com)

    Returns:
        Authentication check results including SPF, DMARC, DKIM status
    """
    if not AUTH_CHECKER_AVAILABLE:
        raise HTTPException(status_code=503, detail="Email authentication checker not available")

    try:
        auth_result = check_email_authentication(email)

        return {
            "domain": auth_result.domain,
            "overall_score": auth_result.overall_score,
            "is_authenticated": auth_result.is_authenticated,
            "summary": auth_result.summary,
            "spf": {
                "status": auth_result.spf.status,
                "is_valid": auth_result.spf.is_valid,
                "record": auth_result.spf.record,
                "all_mechanism": auth_result.spf.all_mechanism,
            },
            "dmarc": {
                "status": auth_result.dmarc.status,
                "is_valid": auth_result.dmarc.is_valid,
                "policy": auth_result.dmarc.policy,
                "record": auth_result.dmarc.record,
            },
            "dkim": {
                "status": auth_result.dkim.status,
                "has_record": auth_result.dkim.has_dkim_record,
                "selector": auth_result.dkim.selector,
            },
            "checks_performed": auth_result.checks_performed,
        }

    except Exception as e:
        logger.error(f"Auth check failed for {email}: {e}")
        raise HTTPException(status_code=502, detail="Authentication check temporarily unavailable") from e


@email_router.get("/health")
async def email_health_check():
    """Health check for email scanning service"""
    return {
        "status": "healthy",
        "service": "email-scanner",
        "auth_checker_available": AUTH_CHECKER_AVAILABLE,
        "features": {
            "safe_browsing": bool(os.getenv("GOOGLE_SAFE_BROWSING_KEY")),
            "whois_domain_age": bool(os.getenv("WHOIS_API_KEY")),
            "nlp_analysis": os.getenv("ENABLE_NLP_ANALYSIS", "true").lower() == "true",
            "redirect_resolution": os.getenv("ENABLE_REDIRECT_RESOLUTION", "true").lower() == "true",
            "ai_explanation": bool(os.getenv("GROQ_API_KEY")),
        },
        "timestamp": datetime.now().isoformat(),
    }


# ============================================
# Standalone AI Explanation Endpoint
# ============================================
class ExplainThreatRequest(BaseModel):
    """Request for standalone threat explanation"""
    threat_score: int = Field(..., description="Threat score 0-100")
    threat_level: str = Field(..., description="safe/suspicious/dangerous")
    summary: str = Field("", description="Scan summary")
    reasons: List[str] = Field(default_factory=list, description="Scan reasons")
    sender_email: str = Field(..., description="Sender email")
    details: Dict[str, Any] = Field(default_factory=dict, description="Scan details dict")


@email_router.post("/explain-threat")
async def explain_threat(request: ExplainThreatRequest):
    """
    Generate an AI-powered explanation for a threat scan result.

    Useful when the client wants to generate or regenerate an explanation
    for a scan that was already performed.
    """
    groq_key = os.getenv("GROQ_API_KEY", "").strip()
    if not groq_key:
        raise HTTPException(status_code=503, detail="AI explanation service not configured (GROQ_API_KEY missing)")

    try:
        explanation = await generate_threat_explanation(
            threat_score=request.threat_score,
            threat_level=request.threat_level,
            summary=request.summary,
            reasons=request.reasons,
            sender_email=request.sender_email,
            details=request.details,
        )
        if not explanation:
            raise HTTPException(status_code=502, detail="AI explanation generation returned empty result")

        return {
            "success": True,
            "explanation": explanation.model_dump() if hasattr(explanation, 'model_dump') else explanation.dict(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI explanation endpoint failed: {e}")
        raise HTTPException(status_code=500, detail=f"Explanation generation failed: {str(e)}") from e


# ============================================
# OAuth Token Verification Endpoint
# ============================================
class VerifyOAuthTokenRequest(BaseModel):
    """Request to verify an OAuth access token server-side"""
    access_token: str = Field(..., description="OAuth access token to verify")
    expected_email: Optional[str] = Field(None, description="Expected email to validate against")


@email_router.post("/verify-oauth-token")
async def verify_oauth_token(request: VerifyOAuthTokenRequest):
    """
    Verify a Google OAuth access token server-side.

    This endpoint contacts Google's tokeninfo endpoint to verify the token
    is valid, not expired, and matches the expected audience/email.
    """
    if not request.access_token or len(request.access_token) < 20:
        raise HTTPException(status_code=400, detail="Invalid access token format")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"access_token": request.access_token},
            )

        if resp.status_code != 200:
            return {
                "valid": False,
                "error": "Token validation failed",
                "status_code": resp.status_code,
            }

        token_info = resp.json()

        # Validate audience matches our client ID
        google_client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        aud = token_info.get("aud", "")
        if google_client_id and aud != google_client_id:
            return {
                "valid": False,
                "error": "Token audience mismatch",
                "expected_aud": google_client_id[:20] + "...",
            }

        # Check email if provided
        token_email = token_info.get("email", "")
        if request.expected_email and token_email:
            if token_email.lower() != request.expected_email.lower():
                return {
                    "valid": False,
                    "error": "Token email mismatch",
                }

        # Check scopes include Gmail access
        scopes = token_info.get("scope", "")
        has_gmail_scope = "gmail" in scopes.lower()

        return {
            "valid": True,
            "email": token_email,
            "expires_in": token_info.get("expires_in"),
            "scopes": scopes.split(" ") if scopes else [],
            "has_gmail_scope": has_gmail_scope,
            "email_verified": token_info.get("email_verified", "false") == "true",
        }

    except httpx.RequestError as e:
        logger.error(f"OAuth token verification failed: {e}")
        raise HTTPException(status_code=502, detail="Failed to contact Google tokeninfo endpoint") from e
    except Exception as e:
        logger.error(f"OAuth token verification error: {e}")
        raise HTTPException(status_code=500, detail=f"Token verification failed: {str(e)}") from e
