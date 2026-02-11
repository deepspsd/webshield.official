"""
Email Scanning Routes for Gmail Extension
Provides email-specific threat analysis endpoints with real SPF/DMARC verification
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

from .utils import WebShieldDetector

# Import our auth checker for real DNS lookups
try:
    from .auth_checker import check_email_authentication

    AUTH_CHECKER_AVAILABLE = True
except ImportError:
    AUTH_CHECKER_AVAILABLE = False
    logging.warning("auth_checker not available, using fallback auth analysis")

logger = logging.getLogger(__name__)

email_router = APIRouter(prefix="/email", tags=["Email"])


# Request/Response Models
class EmailHeaders(BaseModel):
    """Email authentication headers"""

    spf: Optional[str] = Field(None, description="SPF status")
    dkim: Optional[str] = Field(None, description="DKIM status")
    dmarc: Optional[str] = Field(None, description="DMARC status")
    via: Optional[str] = Field(None, description="Via header")


class EmailMetadata(BaseModel):
    """Email metadata for scanning"""

    sender_email: EmailStr = Field(..., description="Sender email address")
    sender_name: Optional[str] = Field(None, description="Sender display name")
    subject: Optional[str] = Field(None, description="Email subject")
    links: List[str] = Field(default_factory=list, description="URLs found in email")
    attachment_hashes: List[str] = Field(default_factory=list, description="Attachment file hashes")
    headers: Optional[EmailHeaders] = Field(None, description="Email headers")
    user_email: Optional[EmailStr] = Field(None, description="Recipient email address")
    gmail_message_id: Optional[str] = Field(None, description="Gmail message ID")
    thread_id: Optional[str] = Field(None, description="Gmail thread ID")


class EmailScanRequest(BaseModel):
    """Request to scan email metadata"""

    email_metadata: EmailMetadata = Field(..., description="Email metadata to scan")
    scan_type: str = Field("full", description="Type of scan (full, quick)")


class SenderReputation(BaseModel):
    """Sender reputation analysis"""

    domain: str = Field("", description="Sender domain")
    reputation_score: int = Field(..., description="Reputation score 0-100")
    is_trusted_domain: bool = Field(..., description="Whether domain is trusted")
    domain_age_days: Optional[int] = Field(None, description="Domain age in days")
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


class LinkAnalysis(BaseModel):
    """Link analysis results"""

    links: List[str] = Field(default_factory=list, description="Links found")
    suspicious_links: List[str] = Field(default_factory=list, description="Suspicious links")
    malicious_links: List[str] = Field(default_factory=list, description="Malicious links")
    vt_suspicious_links: List[str] = Field(default_factory=list, description="Links flagged suspicious by VirusTotal")
    vt_malicious_links: List[str] = Field(default_factory=list, description="Links flagged malicious by VirusTotal")
    vt_scanned_links: int = Field(0, description="Number of links scanned via VirusTotal")
    vt_scan_timed_out: bool = Field(False, description="Whether VirusTotal scanning timed out")
    link_count: int = Field(0, description="Total link count")
    risk_score: int = Field(0, description="Link risk score 0-100")
    link_scan_results: Dict[str, dict] = Field(default_factory=dict, description="Per-link scan results")


class ContentAnalysis(BaseModel):
    """Content analysis results"""

    phishing_keywords_found: int = Field(0, description="Count of phishing keywords found")
    detected_keywords: List[str] = Field(default_factory=list, description="Detected phishing keywords")


class EmailScanDetails(BaseModel):
    """Detailed scan results"""

    sender_reputation: SenderReputation
    header_analysis: HeaderAnalysis
    link_analysis: LinkAnalysis
    content_analysis: ContentAnalysis


class EmailScanResponse(BaseModel):
    """Response from email scan"""

    threat_score: int = Field(..., description="Overall threat score 0-100")
    threat_level: str = Field(..., description="Threat level (safe, suspicious, malicious)")
    summary: str = Field(..., description="Human-readable summary")
    reasons: List[str] = Field(default_factory=list, description="Reasons for the assessment")
    details: EmailScanDetails = Field(..., description="Detailed analysis")
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
        is_disposable=is_disposable,
        is_free_provider=is_free,
        domain_age_days=None,  # Would require external API
    )


def analyze_content(subject: Optional[str]) -> ContentAnalysis:
    """Lightweight content analysis (subject-only) for Gmail extension reports."""

    text = (subject or "").lower()
    if not text:
        return ContentAnalysis(phishing_keywords_found=0, detected_keywords=[])

    phishing_keywords = [
        "urgent",
        "immediately",
        "action required",
        "verify",
        "suspended",
        "security alert",
        "confirm",
        "password",
        "reset",
        "invoice",
        "payment",
        "refund",
        "wire transfer",
        "gift card",
        "login",
        "signin",
    ]

    detected = [k for k in phishing_keywords if k in text]
    return ContentAnalysis(phishing_keywords_found=len(detected), detected_keywords=detected[:10])


def analyze_headers(headers: Optional[EmailHeaders], sender_email: Optional[str] = None) -> HeaderAnalysis:
    """
    Analyze email authentication using real DNS lookups for SPF/DMARC/DKIM.

    If sender_email is provided and auth_checker is available, performs real
    DNS lookups. Otherwise falls back to headers provided by the client.
    """

    # Try real DNS-based authentication check first
    if AUTH_CHECKER_AVAILABLE and sender_email:
        try:
            logger.info(f"Performing real DNS auth check for: {sender_email}")
            auth_result = check_email_authentication(sender_email)

            # IMPORTANT: DNS posture is not the same as message-level SPF/DKIM/DMARC evaluation.
            # We therefore expose posture separately and keep message-level status as unknown
            # unless the client provided real header evaluation.

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

            # IMPORTANT: DNS posture/configuration is not message authentication.
            # We only mark is_authenticated when we have message-level results.
            msg_is_authenticated = (client_spf == "pass" or client_dkim == "pass") and client_dmarc != "fail"

            # Keep score as a blend: if we have message-level signals, use those; otherwise keep posture score.
            msg_score = 0
            if client_spf == "pass":
                msg_score += 33
            elif client_spf == "fail":
                msg_score -= 20
            if client_dkim == "pass":
                msg_score += 33
            elif client_dkim == "fail":
                msg_score -= 20
            if client_dmarc == "pass":
                msg_score += 34
            elif client_dmarc == "fail":
                msg_score -= 20
            msg_score = max(0, min(100, msg_score))

            blended_score = msg_score if (client_spf, client_dkim, client_dmarc) != ("unknown", "unknown", "unknown") else auth_result.overall_score

            return HeaderAnalysis(
                spf_status=client_spf,
                dkim_status=client_dkim,
                dmarc_status=client_dmarc,
                spf_posture=spf_posture,
                dkim_posture=dkim_posture,
                dmarc_posture=dmarc_posture,
                is_authenticated=bool(msg_is_authenticated),
                authentication_score=int(blended_score or 0),
            )

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
    )


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
        # PayPal impersonation
        (r"paypal", r"paypa[l1]|paypai|peypal|paypaI"),
        # Apple impersonation
        (r"apple", r"app[l1]e|app1e|appie"),
        # Amazon impersonation
        (r"amazon", r"amaz[o0]n|arnazon|amazom"),
        # Microsoft impersonation
        (r"microsoft", r"micr[o0]soft|mircosoft|m1crosoft"),
        # Netflix impersonation
        (r"netflix", r"netf[l1]ix|netfiix|netfl1x"),
        # Google impersonation
        (r"google", r"g[o0][o0]gle|googie|g00gle"),
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


def calculate_threat_score(
    sender_rep: SenderReputation, header_analysis: HeaderAnalysis, link_analysis: LinkAnalysis
) -> tuple[int, str, str, List[str]]:
    """Calculate overall threat score and assessment"""

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
    if getattr(link_analysis, "vt_malicious_links", None):
        has_suspicious_patterns = True
        pattern_flags.append(f"vt_malicious_links:{len(link_analysis.vt_malicious_links)}")

    if getattr(link_analysis, "vt_suspicious_links", None):
        has_suspicious_patterns = True
        pattern_flags.append(f"vt_suspicious_links:{len(link_analysis.vt_suspicious_links)}")

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

    # === DETERMINE THREAT LEVEL WITH PATTERN ANALYSIS ===
    # Only mark as suspicious/dangerous if we have ACTUAL reasons

    # VirusTotal policy override: any suspicious/malicious engine verdict => dangerous
    vt_any_flagged = bool(getattr(link_analysis, "vt_malicious_links", []) or getattr(link_analysis, "vt_suspicious_links", []))
    if vt_any_flagged:
        threat_level = "dangerous"
        threat_score = max(threat_score, 85)
        summary = "Email contains link(s) flagged by VirusTotal"
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
    if getattr(link_analysis, "vt_malicious_links", None):
        reasons.append(f"⚠️ VirusTotal flagged {len(link_analysis.vt_malicious_links)} malicious link(s)")
    elif getattr(link_analysis, "vt_suspicious_links", None):
        reasons.append(f"⚠️ VirusTotal flagged {len(link_analysis.vt_suspicious_links)} suspicious link(s)")
    elif getattr(link_analysis, "vt_scan_timed_out", False) and getattr(link_analysis, "vt_scanned_links", 0) > 0:
        reasons.append("VirusTotal scan timed out")

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

    # Ensure we have at least 3 reasons
    while len(reasons) < 3:
        reasons.append("✓ Scan completed successfully")

    return threat_score, threat_level, summary, reasons[:5]  # Max 5 reasons


# API Endpoints
@email_router.post("/scan-metadata", response_model=EmailScanResponse)
async def scan_email_metadata(request: EmailScanRequest):
    """
    Scan email metadata for threats

    This endpoint analyzes email metadata including sender reputation,
    authentication headers, and links to determine if an email is safe.
    """
    try:
        logger.info(f"Scanning email from {request.email_metadata.sender_email}")

        # Analyze sender reputation
        sender_rep = analyze_sender_reputation(request.email_metadata.sender_email, request.email_metadata.sender_name)

        # Analyze headers with real DNS auth checking
        header_analysis = analyze_headers(
            request.email_metadata.headers, sender_email=str(request.email_metadata.sender_email)
        )

        # Analyze links (heuristics first)
        link_analysis = analyze_links(request.email_metadata.links)

        # VirusTotal scan for every link. Use separate key for Gmail/email scanning.
        # Time budget is configurable so you can trade off completeness vs latency.
        vt_budget = float(os.getenv("EMAIL_VT_BUDGET_SECONDS", "8.0"))
        vt_key_email = os.getenv("VT_API_KEY2") or os.getenv("VT_API_KEY")
        vt_suspicious, vt_malicious, vt_scanned_count, vt_timed_out = await analyze_links_virustotal(
            request.email_metadata.links, total_budget_seconds=vt_budget, api_key=vt_key_email
        )
        link_analysis.vt_suspicious_links = vt_suspicious
        link_analysis.vt_malicious_links = vt_malicious
        link_analysis.vt_scanned_links = vt_scanned_count
        link_analysis.vt_scan_timed_out = vt_timed_out

        # Analyze subject for lightweight content warnings
        content_analysis = analyze_content(request.email_metadata.subject)

        # Calculate overall threat score
        threat_score, threat_level, summary, reasons = calculate_threat_score(sender_rep, header_analysis, link_analysis)

        # Build response
        response = EmailScanResponse(
            threat_score=threat_score,
            threat_level=threat_level,
            summary=summary,
            reasons=reasons,
            details=EmailScanDetails(
                sender_reputation=sender_rep,
                header_analysis=header_analysis,
                link_analysis=link_analysis,
                content_analysis=content_analysis,
            ),
            scanned_at=datetime.now(),
        )

        logger.info(
            f"Email scan complete: {request.email_metadata.sender_email} - "
            f"Threat: {threat_score}/100 ({threat_level})"
        )

        return response

    except Exception as e:
        logger.error(f"Error scanning email metadata: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to scan email: {str(e)}") from e


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
        raise HTTPException(status_code=500, detail=f"Authentication check failed: {str(e)}") from e


@email_router.get("/health")
async def email_health_check():
    """Health check for email scanning service"""
    return {
        "status": "healthy",
        "service": "email-scanner",
        "auth_checker_available": AUTH_CHECKER_AVAILABLE,
        "timestamp": datetime.now().isoformat(),
    }
