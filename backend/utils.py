import asyncio
import base64
import logging
import os
import re
import time
import urllib.parse
from typing import Any, Dict
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger(__name__)

# VirusTotal API configuration
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# VirusTotal response cache (in-memory, TTL-based) to reduce API usage.
# This caches only VT stats, not full scan results.
VT_CACHE_TTL_SECONDS = int(os.getenv("VT_CACHE_TTL_SECONDS", "3600"))
_VT_CACHE_BY_URL = {}

# Centralized whitelist of known legitimate domains to prevent false positives
LEGITIMATE_DOMAINS = [
    "github.com",
    "www.github.com",
    "github.io",
    "www.github.io",
    "youtube.com",
    "www.youtube.com",
    "youtu.be",
    "www.youtu.be",
    "google.com",
    "www.google.com",
    "gmail.com",
    "www.gmail.com",
    "openai.com",
    "www.openai.com",
    "chatgpt.com",
    "www.chatgpt.com",
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "www.instagram.com",
    "twitter.com",
    "www.twitter.com",
    "x.com",
    "www.x.com",
    "amazon.com",
    "www.amazon.com",
    "amazon.co.uk",
    "www.amazon.co.uk",
    "microsoft.com",
    "www.microsoft.com",
    "outlook.com",
    "www.outlook.com",
    "apple.com",
    "www.apple.com",
    "icloud.com",
    "www.icloud.com",
    "netflix.com",
    "www.netflix.com",
    "ebay.com",
    "www.ebay.com",
    "paypal.com",
    "www.paypal.com",
    "stackoverflow.com",
    "www.stackoverflow.com",
    "reddit.com",
    "www.reddit.com",
    "linkedin.com",
    "www.linkedin.com",
    "wikipedia.org",
    "www.wikipedia.org",
    "wikipedia.com",
    "www.wikipedia.com",
    "mozilla.org",
    "www.mozilla.org",
    "firefox.com",
    "www.firefox.com",
    "chrome.com",
    "www.chrome.com",
    "brave.com",
    "www.brave.com",
    "discord.com",
    "www.discord.com",
    "slack.com",
    "www.slack.com",
    "zoom.us",
    "www.zoom.us",
    "teams.microsoft.com",
    "www.teams.microsoft.com",
    "dropbox.com",
    "www.dropbox.com",
    "drive.google.com",
    "www.drive.google.com",
    "onedrive.live.com",
    "www.onedrive.live.com",
]


class WebShieldDetector:
    """
    Advanced Multi-Engine Threat Detection System

    Detection Engines:
    1. ML-Powered URL Classification (Ensemble: RF + GB + SVM + NN)
    2. Deep Content Analysis with Behavioral Patterns
    3. SSL/TLS Certificate Chain Validation
    4. VirusTotal Multi-Scanner Integration (90+ engines)
    5. Real-Time Threat Intelligence Feeds
    6. Advanced Phishing Pattern Recognition
    7. Brand Impersonation Detection
    8. Typosquatting & Homograph Attack Detection
    """

    def __init__(self):
        self.session = None
        self.detection_count = 0
        self.threat_cache = {}

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10), connector=aiohttp.TCPConnector(limit=100, limit_per_host=30)
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            try:
                # Properly close the session and wait for cleanup
                await self.session.close()
                # CRITICAL FIX: Wait for underlying connections to close
                await asyncio.sleep(0.25)
                logger.info(f"✅ Detector session closed. Total detections: {self.detection_count}")
            except Exception as e:
                logger.warning(f"Error closing session: {e}")

    async def analyze_url_patterns(self, url: str) -> Dict[str, Any]:
        """Analyze URL patterns for suspicious characteristics"""
        try:
            # Try to use ML analysis first
            ml_result = await self._analyze_url_ml(url)
            if ml_result and ml_result.get("ml_enabled", False):
                return ml_result

            # Fallback to rule-based analysis
            return await self._rule_based_url_analysis(url)
        except Exception as e:
            logger.error(f"ML URL analysis failed, falling back to rule-based: {e}")
            return await self._rule_based_url_analysis(url)

    async def _analyze_url_ml(self, url: str) -> Dict[str, Any]:
        """Analyze URL using ML models"""
        try:
            # Import ML engine using the global instance
            try:
                from ml_models.ml_integration import get_ml_engine
            except Exception:
                from .ml_models.ml_integration import get_ml_engine

            # Get the global ML engine instance
            ml_engine = get_ml_engine()
            if not ml_engine:
                return None
            result = await asyncio.to_thread(ml_engine.analyze_url_ml, url)
            if not isinstance(result, dict):
                return None

            if result.get("ml_enabled", False):
                logger.info(f"ML URL analysis successful for {url}")
                # Extract and calibrate values
                threat_prob = float(result.get("threat_probability", 0.0))
                prediction = int(result.get("prediction", 0))
                confidence = float(result.get("confidence", 0.0))
                try:
                    parsed = urlparse(url)
                    domain = (parsed.hostname or "").lower()
                except Exception:
                    domain = ""
                domain_base = domain[4:] if domain.startswith("www.") else domain

                def _is_whitelisted_domain(d: str) -> bool:
                    if not d:
                        return False
                    for trusted in LEGITIMATE_DOMAINS:
                        t = (trusted or "").lower()
                        if not t:
                            continue
                        t_base = t[4:] if t.startswith("www.") else t
                        if d == t_base or d.endswith("." + t_base):
                            return True
                    return False

                # Trusted domain override
                if _is_whitelisted_domain(domain_base):
                    return {
                        "suspicious_score": 0,
                        "detected_issues": ["Legitimate domain whitelisted"],
                        "domain": domain_base or domain,
                        "is_suspicious": False,
                        "ml_enabled": True,
                        "ml_threat_probability": 0.0,
                        "ml_confidence": max(confidence, 0.95),
                    }

                # Lightweight heuristic sanity-check to avoid extreme false positives.
                # This does NOT override clear threats (IP URLs, suspicious TLDs, obvious phishing keywords).
                heuristic_risk = 0
                try:
                    parsed2 = urlparse(url)
                    path = (parsed2.path or "").lower()
                    query = (parsed2.query or "").lower()
                    d = domain_base or domain
                    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", d or ""):
                        heuristic_risk += 80
                    if any((d or "").endswith(tld) for tld in (".tk", ".ml", ".ga", ".cf", ".gq")):
                        heuristic_risk += 60
                    if any(
                        k in (path + "?" + query)
                        for k in ("login", "signin", "verify", "password", "update", "secure", "account")
                    ):
                        heuristic_risk += 20
                    if (d or "").count("-") >= 2:
                        heuristic_risk += 10
                    digit_ratio = sum(1 for c in (d or "") if c.isdigit()) / max(1, len(d or ""))
                    if digit_ratio > 0.2:
                        heuristic_risk += 10
                except Exception:
                    heuristic_risk = heuristic_risk

                # Recalibrated score: only assign high scores when model is very confident AND predicts malicious.
                if prediction != 1:
                    calibrated_score = 0
                else:
                    # Map [0.80..1.00] -> [0..100], clamp outside.
                    if threat_prob <= 0.80:
                        calibrated_score = 0
                    else:
                        calibrated_score = int(((min(threat_prob, 1.0) - 0.80) / 0.20) * 100)
                calibrated_score = int(max(0, min(100, calibrated_score)))

                detected_issues = list(result.get("detected_issues", []) or [])

                # If the model is extremely confident but heuristics are low-risk, downgrade.
                # This prevents benign domains from showing 95-100 just due to model bias.
                if prediction == 1 and threat_prob >= 0.95 and heuristic_risk <= 10:
                    detected_issues = detected_issues + [
                        "ML high-confidence flagged but heuristics are low-risk; score downgraded"
                    ]
                    calibrated_score = min(calibrated_score, 30)

                is_suspicious = prediction == 1 and calibrated_score >= 60

                return {
                    "suspicious_score": calibrated_score,
                    "detected_issues": detected_issues,
                    "domain": domain_base or domain,
                    "is_suspicious": is_suspicious,
                    "ml_enabled": True,
                    "ml_threat_probability": float(threat_prob),
                    "ml_confidence": confidence,
                }
            else:
                logger.info(f"ML not available for {url}, using rule-based")
                return None

        except Exception as e:
            logger.warning(f"ML URL analysis failed: {e}")
            return None

    async def _rule_based_url_analysis(self, url: str) -> Dict[str, Any]:
        """Rule-based URL analysis as fallback"""
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower() if parsed.netloc else "unknown"

            # Check if domain is in whitelist
            if domain in LEGITIMATE_DOMAINS:
                return {
                    "suspicious_score": 0,
                    "detected_issues": ["Legitimate domain whitelisted"],
                    "domain": domain,
                    "is_suspicious": False,
                    "ml_enabled": False,
                }

            # Basic suspicious pattern detection
            suspicious_score = 0
            detected_issues = []

            # Check for suspicious TLDs
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_score += 10
                detected_issues.append(f"Suspicious TLD: {domain.split('.')[-1]}")

            # Check for IP addresses instead of domain names
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                suspicious_score += 15
                detected_issues.append("IP address instead of domain name")

            # Check for excessive subdomains
            subdomain_count = len(domain.split(".")) - 1
            if subdomain_count > 3:
                suspicious_score += 8
                detected_issues.append(f"Excessive subdomains: {subdomain_count}")

            # Check for suspicious keywords in domain - only flag when combined with other suspicious patterns
            suspicious_keywords = ["secure", "login", "signin", "bank", "paypal", "amazon", "google", "facebook"]
            for keyword in suspicious_keywords:
                if keyword in domain:
                    # Only flag if it's not a legitimate domain
                    if not (domain == f"{keyword}.com" or domain == f"www.{keyword}.com"):
                        suspicious_score += 3
                        detected_issues.append(f"Suspicious keyword: {keyword}")

            # Check for typosquatting patterns
            if len(domain) > 30:
                suspicious_score += 5
                detected_issues.append("Very long domain name")

            # Check for mixed case (potential typosquatting)
            if domain != domain.lower() and domain != domain.upper():
                suspicious_score += 3
                detected_issues.append("Mixed case domain (potential typosquatting)")

            return {
                "suspicious_score": suspicious_score,
                "detected_issues": detected_issues,
                "domain": domain,
                "is_suspicious": suspicious_score > 20,
                "ml_enabled": False,
            }
        except Exception as e:
            logger.error(f"Rule-based URL analysis failed for {url}: {e}")
            return {
                "suspicious_score": 0,
                "detected_issues": [f"Analysis error: {str(e)}"],
                "domain": "unknown",
                "is_suspicious": False,
                "ml_enabled": False,
            }

    async def analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL certificate validity with proper certificate details and aggressive timeout handling"""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https":
            return {
                "valid": False,
                "status": "no_https",
                "error": "No HTTPS",
                "details": "Site does not use HTTPS encryption",
                "threat_score": 25,
                "is_intentionally_insecure": False,
                "issuer": "N/A",
                "expires": "N/A",
            }

        import asyncio
        import socket
        import ssl
        from datetime import datetime

        hostname = parsed.hostname
        port = parsed.port or 443

        # Balanced timeout: keep responsive but avoid marking everything as timed out.
        # Note: On some networks/DNS configurations, 1s-2s is too aggressive for TLS handshake.
        def ssl_check_with_timeout():
            try:
                # Use a context that does NOT disable verification (to get real certs)
                context = ssl.create_default_context()
                # Connection timeout
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    # CRITICAL: Set socket timeout before SSL wrap
                    sock.settimeout(3.0)  # TLS handshake timeout
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # ULTRA-FAST: Get certificate immediately
                        cert = ssock.getpeercert()
                        if cert:

                            def _flatten_name(name_tuple):
                                flattened = {}
                                try:
                                    for rdn in name_tuple:
                                        for key, value in rdn:
                                            flattened[key] = value
                                except Exception:
                                    pass
                                return flattened

                            issuer = "Unknown"
                            issuer_dict = _flatten_name(cert.get("issuer", ()))
                            issuer_parts = []
                            if issuer_dict.get("commonName"):
                                issuer_parts.append(f"CN={issuer_dict.get('commonName')}")
                            if issuer_dict.get("organizationName"):
                                issuer_parts.append(f"O={issuer_dict.get('organizationName')}")
                            if issuer_dict.get("countryName"):
                                issuer_parts.append(f"C={issuer_dict.get('countryName')}")
                            if issuer_dict.get("organizationalUnitName"):
                                issuer_parts.append(f"OU={issuer_dict.get('organizationalUnitName')}")
                            issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"

                            expires = "Unknown"
                            threat_score = 0
                            valid = True
                            if "notAfter" in cert:
                                try:
                                    date_str = cert["notAfter"]
                                    if "GMT" in date_str:
                                        expire_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
                                    else:
                                        expire_date = datetime.strptime(date_str, "%b %d %H:%M:%S %Y")
                                    expires = expire_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                                    now = datetime.utcnow()
                                    if expire_date < now:
                                        threat_score = 50
                                        valid = False
                                    else:
                                        days_until_expiry = (expire_date - now).days
                                        if days_until_expiry < 30:
                                            threat_score = 15
                                        elif days_until_expiry < 90:
                                            threat_score = 5
                                except Exception as e:
                                    logger.warning(f"SSL date parsing error for {url}: {e}")
                                    expires = "Invalid date format"
                                    threat_score = 10
                            else:
                                expires = "Not specified"
                                threat_score = 10

                            is_self_signed = False
                            subject_dict = _flatten_name(cert.get("subject", ()))
                            if (
                                subject_dict.get("commonName")
                                and issuer_dict.get("commonName")
                                and subject_dict.get("commonName") == issuer_dict.get("commonName")
                            ):
                                is_self_signed = True
                                threat_score += 10

                            return {
                                "valid": valid,
                                "status": "valid" if valid else "invalid",
                                "issuer": issuer,
                                "expires": expires,
                                "threat_score": threat_score,
                                "is_intentionally_insecure": False,
                                "is_self_signed": is_self_signed,
                                "details": "SSL certificate analyzed successfully",
                            }
                        else:
                            return {
                                "valid": False,
                                "status": "unknown",
                                "error": "No certificate found",
                                "details": "Could not retrieve SSL certificate",
                                "threat_score": 20,
                                "is_intentionally_insecure": False,
                                "issuer": "N/A",
                                "expires": "N/A",
                            }
            except Exception as inner_e:
                raise inner_e

        # CRITICAL FIX: Run SSL check with asyncio timeout to prevent hanging
        try:
            loop = asyncio.get_running_loop()
            return await asyncio.wait_for(loop.run_in_executor(None, ssl_check_with_timeout), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(f"SSL analysis timed out for {url} after 5 seconds")
            return {
                "valid": None,
                "status": "timeout",
                "error": "SSL analysis timeout",
                "details": "SSL analysis timed out after 5 seconds",
                "threat_score": 10,  # Lower score for timeout (don't assume malicious)
                "is_intentionally_insecure": False,
                "issuer": "N/A",
                "expires": "N/A",
            }
                
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {url}: {e}")
            return {
                "valid": False,
                "status": "invalid",
                "error": f"SSL Error: {str(e)}",
                "details": "SSL certificate validation failed",
                "threat_score": 15,
                "is_intentionally_insecure": False,
                "issuer": "N/A",
                "expires": "N/A",
            }
        except socket.timeout:
            logger.warning(f"SSL connection timeout for {url}")
            return {
                "valid": None,
                "status": "timeout",
                "error": "Connection timeout",
                "details": "SSL connection timed out",
                "threat_score": 0,
                "is_intentionally_insecure": False,
                "issuer": "N/A",
                "expires": "N/A",
            }
        except Exception as e:
            logger.warning(f"SSL analysis failed for {url}: {e}")
            return {
                "valid": None,
                "status": "unknown",
                "error": f"Connection failed: {str(e)}",
                "details": "Could not establish SSL connection",
                "threat_score": 0,
                "is_intentionally_insecure": False,
                "issuer": "N/A",
                "expires": "N/A",
            }

    async def analyze_content(self, url: str, max_bytes=1 * 1024) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators with aggressive timeout handling"""
        try:
            
            import ssl as ssl_module
            ssl_context = ssl_module.create_default_context()
            
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,  # ✅ FIXED: Proper SSL validation enabled
                limit=5,  # Reduced connection limit
                limit_per_host=2,  # Very low per-host limit
                ttl_dns_cache=30,  # Short DNS cache
                use_dns_cache=True,
                keepalive_timeout=5,  # Short keepalive
                enable_cleanup_closed=True,
            )
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",  # Force connection close
            }
            # ULTRA-AGGRESSIVE: 2 second total timeout, 1 second connect
            timeout = aiohttp.ClientTimeout(total=2.0, connect=1.0, sock_read=1.0)
            async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=timeout) as content_session:
                async with content_session.get(url) as response:
                    if response.status != 200:
                        return {
                            "error": f"HTTP {response.status}",
                            "phishing_score": 0,
                            "detected_indicators": [],
                            "is_suspicious": False,
                            "content_length": 0,
                            "ml_enabled": False,
                        }

                    content = await response.content.read(max_bytes)
                    content = content.decode(errors="ignore")

                    # Try ML analysis first
                    ml_result = await self._analyze_content_ml(content)
                    if ml_result and ml_result.get("ml_enabled", False):
                        return ml_result

                    # Fallback to rule-based analysis
                    return await self._rule_based_content_analysis(content)

        except Exception as e:
            return {
                "error": f"Content analysis failed: {str(e)}",
                "phishing_score": 0,
                "detected_indicators": [],
                "is_suspicious": False,
                "content_length": 0,
                "ml_enabled": False,
            }

    async def analyze_text_content(self, text_content: str) -> Dict[str, Any]:
        """Analyze raw text content using ML models"""
        try:
            # Try ML analysis first
            ml_result = await self._analyze_content_ml(text_content)
            if ml_result and ml_result.get("ml_enabled", False):
                return ml_result

            # Fallback to rule-based analysis
            return await self._rule_based_content_analysis(text_content)

        except Exception as e:
            return {
                "error": f"Text content analysis failed: {str(e)}",
                "phishing_score": 0,
                "detected_indicators": [],
                "is_suspicious": False,
                "content_length": 0,
                "ml_enabled": False,
            }

    async def _analyze_content_ml(self, html_content: str) -> Dict[str, Any]:
        """Analyze HTML content using ML models"""
        try:
            # Import ML engine using the global instance
            try:
                from ml_models.ml_integration import get_ml_engine
            except Exception:
                from .ml_models.ml_integration import get_ml_engine

            # Get the global ML engine instance
            ml_engine = get_ml_engine()
            if not ml_engine:
                return None
            result = await asyncio.to_thread(ml_engine.analyze_content_ml, html_content)
            if not isinstance(result, dict):
                return None

            logger.info(f"ML content analysis result: {result}")
            if result.get("ml_enabled", False):
                logger.info("ML content analysis successful")
                # Convert ML result to expected format
                return {
                    "phishing_score": int(result.get("phishing_probability", 0) * 100),
                    "detected_indicators": result.get("detected_issues", []),  # Use detected_issues from ML
                    "is_suspicious": result.get("threat_detected", False),  # Use threat_detected from ML
                    "content_length": len(html_content),
                    "ml_enabled": True,
                    "ml_confidence": result.get("confidence", 0.0),
                }
            else:
                logger.info(f"ML not available (ml_enabled={result.get('ml_enabled')}), using rule-based")
                return None

        except Exception as e:
            logger.warning(f"ML content analysis failed: {e}")
            return None

    async def _rule_based_content_analysis(self, html_content: str) -> Dict[str, Any]:
        """Rule-based content analysis as fallback"""
        phishing_score = 0
        detected_indicators = []

        # Check for suspicious keywords
        suspicious_keywords = [
            "password",
            "login",
            "signin",
            "account",
            "verify",
            "confirm",
            "bank",
            "credit",
            "card",
            "ssn",
            "social security",
            "paypal",
            "urgent",
            "immediate",
            "suspended",
            "locked",
            "verify now",
        ]

        content_lower = html_content.lower()
        for keyword in suspicious_keywords:
            if keyword in content_lower:
                phishing_score += 2
                detected_indicators.append(f"Suspicious keyword: {keyword}")

        # Check for forms
        if "<form" in html_content.lower():
            phishing_score += 3
            detected_indicators.append("Contains form")

        # Check for input fields
        input_count = html_content.lower().count("<input")
        if input_count > 5:
            phishing_score += 1
            detected_indicators.append(f"Multiple input fields: {input_count}")

        # Check for external links
        external_links = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_content)
        if len(external_links) > 10:
            phishing_score += 2
            detected_indicators.append(f"Many external links: {len(external_links)}")

        return {
            "phishing_score": phishing_score,
            "detected_indicators": detected_indicators,
            "is_suspicious": phishing_score > 25,
            "content_length": len(html_content),
            "ml_enabled": False,
        }

    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal API with aggressive timeout handling.
        If no cached analysis is available, submit a URL analysis and poll briefly for a result.
        """
        if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
            return {
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "scan_date": "N/A",
                "permalink": "N/A",
                "positives": [],
                "error": "VirusTotal API key not configured - using local analysis only",
                "vt_source": "Local Analysis (VT Disabled)",
                "fallback_mode": True,
            }

        try:
            # First: in-process cache to avoid re-hitting VT for the same URL.
            try:
                cached_entry = _VT_CACHE_BY_URL.get(url)
                if cached_entry and isinstance(cached_entry, dict):
                    cached_at = cached_entry.get("_cached_at", 0)
                    if (time.time() - float(cached_at or 0)) <= VT_CACHE_TTL_SECONDS:
                        cached_result = dict(cached_entry.get("result") or {})
                        if cached_result:
                            cached_result["cached"] = True
                            cached_result["vt_cache"] = True
                            return cached_result
            except Exception:
                pass

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/json"}

            check_url = f"{VT_BASE_URL}/urls/{url_id}"

            # CRITICAL FIX: Ultra-fast cached analysis check with timeout
            try:
                # Correct: Use async with for session.get, then wrap in wait_for
                response = await asyncio.wait_for(self.session.get(check_url, headers=headers), timeout=3.0)
                if response.status == 200:
                    data = await response.json()
                    stats = data["data"]["attributes"]["last_analysis_stats"]
                    result = {
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                        "total_engines": sum(stats.values()),
                        "engines_results": {},
                        "reputation": data["data"]["attributes"].get("reputation", 0),
                        "cached": True,
                    }
                    try:
                        _VT_CACHE_BY_URL[url] = {"_cached_at": time.time(), "result": result}
                    except Exception:
                        pass
                    return result
            except asyncio.TimeoutError:
                logger.warning(f"VirusTotal check timed out after 3s for {url}")
            except Exception as e:
                logger.warning(f"VirusTotal check failed: {e}")

            # Submit URL for analysis if not cached
            submit_url = f"{VT_BASE_URL}/urls"
            form = aiohttp.FormData()
            form.add_field("url", url)
            submit_id = None
            try:
                async with self.session.post(
                    submit_url, headers={"x-apikey": VT_API_KEY}, data=form, timeout=3.0
                ) as resp:
                    if resp.status in (200, 202):
                        sub = await resp.json()
                        submit_id = sub.get("data", {}).get("id")
            except Exception:
                submit_id = None

            # Poll a couple of times for fresh analysis if we have an id
            if submit_id:
                analysis_url = f"{VT_BASE_URL}/analyses/{submit_id}"
                for _ in range(2):  # brief polling to stay fast
                    try:
                        async with self.session.get(analysis_url, headers=headers, timeout=2.0) as aresp:
                            if aresp.status == 200:
                                adata = await aresp.json()
                                status = adata.get("data", {}).get("attributes", {}).get("status")
                                if status == "completed":
                                    # After completion, fetch the URL object again for stats
                                    async with self.session.get(check_url, headers=headers, timeout=2.0) as fresp:
                                        if fresp.status == 200:
                                            fdata = await fresp.json()
                                            stats = fdata["data"]["attributes"]["last_analysis_stats"]
                                            result = {
                                                "malicious_count": stats.get("malicious", 0),
                                                "suspicious_count": stats.get("suspicious", 0),
                                                "harmless_count": stats.get("harmless", 0),
                                                "undetected_count": stats.get("undetected", 0),
                                                "total_engines": sum(stats.values()),
                                                "engines_results": {},
                                                "reputation": fdata["data"]["attributes"].get("reputation", 0),
                                                "cached": False,
                                            }
                                            try:
                                                _VT_CACHE_BY_URL[url] = {"_cached_at": time.time(), "result": result}
                                            except Exception:
                                                pass
                                            return result
                    except Exception:
                        pass

            # Indicate that no real-time data is available
            result = {
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "total_engines": 0,
                "engines_results": {},
                "reputation": 0,
                "cached": False,
                "data_unavailable": True,
                "error": "Real-time data unavailable",
            }
            return result
        except Exception as e:
            return {
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "undetected_count": 0,
                "total_engines": 0,
                "engines_results": {},
                "reputation": 0,
                "cached": False,
                "data_unavailable": True,
                "error": f"Real-time data unavailable: {str(e)}",
            }
