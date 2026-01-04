"""
Email Authentication Checker (SPF, DKIM, DMARC)
Performs real DNS lookups to verify sender domain authentication records.

This module provides:
- SPF record lookup and validation
- DMARC policy lookup and parsing
- DKIM selector discovery (limited without actual email headers)
- Overall authentication scoring
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:
    import dns.exception
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logging.warning("dnspython not installed. DNS lookups will be simulated.")

logger = logging.getLogger(__name__)

# Cache for DNS lookups (TTL: 5 minutes)
_dns_cache: Dict[str, Tuple[any, float]] = {}
DNS_CACHE_TTL = 300  # 5 minutes


@dataclass
class SPFResult:
    """SPF check result"""

    status: str  # pass, fail, softfail, neutral, none, permerror, temperror
    record: Optional[str] = None
    includes: List[str] = None
    all_mechanism: Optional[str] = None  # +all, -all, ~all, ?all
    is_valid: bool = False

    def __post_init__(self):
        if self.includes is None:
            self.includes = []


@dataclass
class DMARCResult:
    """DMARC check result"""

    status: str  # pass, fail, none, permerror
    record: Optional[str] = None
    policy: Optional[str] = None  # none, quarantine, reject
    subdomain_policy: Optional[str] = None
    pct: int = 100  # Percentage of messages to apply policy
    rua: Optional[str] = None  # Aggregate report URI
    ruf: Optional[str] = None  # Forensic report URI
    is_valid: bool = False


@dataclass
class DKIMResult:
    """DKIM check result (limited without actual email)"""

    status: str  # pass, fail, none
    selector: Optional[str] = None
    has_dkim_record: bool = False


@dataclass
class AuthCheckResult:
    """Complete authentication check result"""

    domain: str
    spf: SPFResult
    dmarc: DMARCResult
    dkim: DKIMResult
    overall_score: int  # 0-100
    is_authenticated: bool
    summary: str
    checks_performed: List[str]


def _get_cached(key: str) -> Optional[any]:
    """Get cached DNS result if not expired"""
    if key in _dns_cache:
        value, timestamp = _dns_cache[key]
        if time.time() - timestamp < DNS_CACHE_TTL:
            return value
        else:
            del _dns_cache[key]
    return None


def _set_cached(key: str, value: any):
    """Set cached DNS result"""
    _dns_cache[key] = (value, time.time())


def extract_domain(email: str) -> Optional[str]:
    """Extract domain from email address"""
    if not email or "@" not in email:
        return None
    return email.split("@")[-1].lower().strip()


def _get_resolver(timeout: float = 5.0) -> "dns.resolver.Resolver":
    """Create a DNS resolver with public DNS servers for reliability"""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    # Use Google and Cloudflare public DNS for reliability
    resolver.nameservers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    return resolver


def check_spf(domain: str, timeout: float = 5.0) -> SPFResult:
    """
    Check SPF record for a domain.

    SPF (Sender Policy Framework) specifies which mail servers are authorized
    to send email on behalf of a domain.
    """
    if not DNS_AVAILABLE:
        return SPFResult(status="unavailable", is_valid=False)

    cache_key = f"spf:{domain}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    try:
        resolver = _get_resolver(timeout)

        # Query TXT records
        answers = resolver.resolve(domain, "TXT")

        spf_record = None
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                spf_record = txt
                break

        if not spf_record:
            result = SPFResult(status="none", is_valid=False)
            _set_cached(cache_key, result)
            return result

        # Parse SPF record
        includes = []
        all_mechanism = None

        # Extract includes
        for match in re.finditer(r"include:([^\s]+)", spf_record):
            includes.append(match.group(1))

        # Check all mechanism
        if " +all" in spf_record or spf_record.endswith("+all"):
            all_mechanism = "+all"  # Dangerous: allows any server
        elif " -all" in spf_record or spf_record.endswith("-all"):
            all_mechanism = "-all"  # Strict: only listed servers
        elif " ~all" in spf_record or spf_record.endswith("~all"):
            all_mechanism = "~all"  # Soft fail: mark but deliver
        elif " ?all" in spf_record or spf_record.endswith("?all"):
            all_mechanism = "?all"  # Neutral

        # Determine validity
        is_valid = all_mechanism in ["-all", "~all"]
        status = "pass" if is_valid else ("softfail" if all_mechanism == "~all" else "neutral")

        result = SPFResult(
            status=status, record=spf_record, includes=includes, all_mechanism=all_mechanism, is_valid=is_valid
        )
        _set_cached(cache_key, result)
        return result

    except dns.resolver.NXDOMAIN:
        result = SPFResult(status="none", is_valid=False)
        _set_cached(cache_key, result)
        return result
    except dns.resolver.NoAnswer:
        result = SPFResult(status="none", is_valid=False)
        _set_cached(cache_key, result)
        return result
    except dns.exception.Timeout:
        return SPFResult(status="temperror", is_valid=False)
    except Exception as e:
        logger.warning(f"SPF check failed for {domain}: {e}")
        return SPFResult(status="permerror", is_valid=False)


def check_dmarc(domain: str, timeout: float = 5.0) -> DMARCResult:
    """
    Check DMARC record for a domain.

    DMARC (Domain-based Message Authentication, Reporting & Conformance)
    tells receiving servers what to do with emails that fail SPF/DKIM checks.
    """
    if not DNS_AVAILABLE:
        return DMARCResult(status="unavailable", is_valid=False)

    cache_key = f"dmarc:{domain}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    try:
        resolver = _get_resolver(timeout)

        # DMARC records are at _dmarc.domain.com
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")

        dmarc_record = None
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=DMARC1"):
                dmarc_record = txt
                break

        if not dmarc_record:
            result = DMARCResult(status="none", is_valid=False)
            _set_cached(cache_key, result)
            return result

        # Parse DMARC record
        policy = None
        subdomain_policy = None
        pct = 100
        rua = None
        ruf = None

        # Extract policy (p=)
        policy_match = re.search(r"\bp=(\w+)", dmarc_record)
        if policy_match:
            policy = policy_match.group(1).lower()

        # Extract subdomain policy (sp=)
        sp_match = re.search(r"\bsp=(\w+)", dmarc_record)
        if sp_match:
            subdomain_policy = sp_match.group(1).lower()

        # Extract percentage (pct=)
        pct_match = re.search(r"\bpct=(\d+)", dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))

        # Extract report URIs
        rua_match = re.search(r"\brua=([^\s;]+)", dmarc_record)
        if rua_match:
            rua = rua_match.group(1)

        ruf_match = re.search(r"\bruf=([^\s;]+)", dmarc_record)
        if ruf_match:
            ruf = ruf_match.group(1)

        # Determine validity - reject or quarantine policies are strong
        is_valid = policy in ["reject", "quarantine"]
        status = "pass" if policy else "none"

        result = DMARCResult(
            status=status,
            record=dmarc_record,
            policy=policy,
            subdomain_policy=subdomain_policy,
            pct=pct,
            rua=rua,
            ruf=ruf,
            is_valid=is_valid,
        )
        _set_cached(cache_key, result)
        return result

    except dns.resolver.NXDOMAIN:
        result = DMARCResult(status="none", is_valid=False)
        _set_cached(cache_key, result)
        return result
    except dns.resolver.NoAnswer:
        result = DMARCResult(status="none", is_valid=False)
        _set_cached(cache_key, result)
        return result
    except dns.exception.Timeout:
        return DMARCResult(status="temperror", is_valid=False)
    except Exception as e:
        logger.warning(f"DMARC check failed for {domain}: {e}")
        return DMARCResult(status="permerror", is_valid=False)


def check_dkim_selector(domain: str, selector: str = "default", timeout: float = 5.0) -> DKIMResult:
    """
    Check if DKIM record exists for a domain with a given selector.

    Note: Without the actual email headers, we can only check if common DKIM
    selectors exist. Real DKIM verification requires the DKIM-Signature header.
    """
    if not DNS_AVAILABLE:
        return DKIMResult(status="unavailable", has_dkim_record=False)

    # Common DKIM selectors used by major providers
    common_selectors = [selector, "google", "selector1", "selector2", "k1", "default", "dkim", "mail"]

    cache_key = f"dkim:{domain}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    try:
        resolver = _get_resolver(timeout)

        for sel in common_selectors:
            try:
                dkim_domain = f"{sel}._domainkey.{domain}"
                answers = resolver.resolve(dkim_domain, "TXT")

                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if "v=DKIM1" in txt or "k=rsa" in txt or "p=" in txt:
                        result = DKIMResult(status="pass", selector=sel, has_dkim_record=True)
                        _set_cached(cache_key, result)
                        return result
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.exception.Timeout:
                continue

        # No DKIM record found
        result = DKIMResult(status="none", has_dkim_record=False)
        _set_cached(cache_key, result)
        return result

    except Exception as e:
        logger.warning(f"DKIM check failed for {domain}: {e}")
        return DKIMResult(status="permerror", has_dkim_record=False)


def check_email_authentication(sender_email: str) -> AuthCheckResult:
    """
    Perform comprehensive email authentication check for a sender.

    This checks SPF, DMARC, and DKIM records for the sender's domain
    and returns an overall authentication score.
    """
    domain = extract_domain(sender_email)
    checks_performed = []

    if not domain:
        return AuthCheckResult(
            domain="unknown",
            spf=SPFResult(status="permerror"),
            dmarc=DMARCResult(status="permerror"),
            dkim=DKIMResult(status="permerror"),
            overall_score=0,
            is_authenticated=False,
            summary="Invalid email address",
            checks_performed=[],
        )

    # Perform all checks
    logger.info(f"Checking email authentication for domain: {domain}")

    spf_result = check_spf(domain)
    checks_performed.append("SPF")

    dmarc_result = check_dmarc(domain)
    checks_performed.append("DMARC")

    dkim_result = check_dkim_selector(domain)
    checks_performed.append("DKIM")

    # Calculate overall score (0-100)
    score = 0

    # SPF scoring (max 35 points)
    if spf_result.status == "pass" and spf_result.all_mechanism == "-all":
        score += 35  # Strict SPF
    elif spf_result.status == "pass" or spf_result.all_mechanism == "~all":
        score += 25  # Soft SPF
    elif spf_result.status == "neutral":
        score += 10
    elif spf_result.status == "none":
        score += 5  # No SPF is slightly better than failed SPF
    # Failed/error SPF = 0

    # DMARC scoring (max 35 points)
    if dmarc_result.is_valid and dmarc_result.policy == "reject":
        score += 35  # Strict DMARC
    elif dmarc_result.is_valid and dmarc_result.policy == "quarantine":
        score += 30  # Moderate DMARC
    elif dmarc_result.policy == "none":
        score += 15  # DMARC exists but monitoring only
    elif dmarc_result.status == "none":
        score += 5  # No DMARC
    # Failed DMARC = 0

    # DKIM scoring (max 30 points)
    if dkim_result.has_dkim_record:
        score += 30  # DKIM record exists
    elif dkim_result.status == "none":
        score += 10  # No DKIM record found (not necessarily bad)
    # Failed DKIM = 0

    # Determine if authenticated
    is_authenticated = (
        (spf_result.is_valid or spf_result.status in ["pass", "neutral"])
        and (dmarc_result.status != "fail")
        and score >= 50
    )

    # Generate summary
    if score >= 80:
        summary = f"Strong email authentication for {domain}"
    elif score >= 60:
        summary = f"Good email authentication for {domain}"
    elif score >= 40:
        summary = f"Basic email authentication for {domain}"
    elif score >= 20:
        summary = f"Weak email authentication for {domain}"
    else:
        summary = f"Poor or missing email authentication for {domain}"

    return AuthCheckResult(
        domain=domain,
        spf=spf_result,
        dmarc=dmarc_result,
        dkim=dkim_result,
        overall_score=score,
        is_authenticated=is_authenticated,
        summary=summary,
        checks_performed=checks_performed,
    )


# Async wrapper for use in FastAPI
async def check_email_authentication_async(sender_email: str) -> AuthCheckResult:
    """Async wrapper for email authentication check"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, check_email_authentication, sender_email)
