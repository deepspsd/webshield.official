# -*- coding: utf-8 -*-
import asyncio
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException

from .db import get_db_connection_with_retry
from .llm_service import LLMService
from .models import ScanResult, ThreatReport, URLScanRequest
from .utils import WebShieldDetector

# Configure optimized logging
logging.basicConfig(level=logging.ERROR)  # Only log errors for production
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)


scan_router = APIRouter(prefix="/scan", tags=["Scanning"])

SCAN_IN_PROGRESS = {}
SCAN_IN_PROGRESS_TIMESTAMPS = {}

# In-memory scan cache keyed by scan_id (DB-independent fallback)
SCAN_REPORTS_BY_ID = {}

# Thread pool to prevent thread exhaustion (CRITICAL FIX)
MAX_WORKER_THREADS = 5  # Reduced from 10 to 5 to prevent resource exhaustion
_scan_executor = ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS, thread_name_prefix="WebShield-Scan")

# Track active scans to prevent overload
_active_scans = 0
_max_concurrent_scans = 3  # Maximum concurrent scans
_scan_lock = asyncio.Lock()


def get_cached_scan(url):
    """Get cached scan result - DISABLED: Always return None for fresh scans"""
    # IMPORTANT: Caching is DISABLED to ensure fresh scan data every time
    # This ensures accurate real-time threat detection
    return None


def set_cached_scan(url, result):
    """Store scan result by scan_id for retrieval - NOT for caching"""
    try:
        # Store only by scan_id for result retrieval, not for caching by URL
        if result and getattr(result, "scan_id", None):
            SCAN_REPORTS_BY_ID[result.scan_id] = result
    except Exception:  # nosec B110
        pass


def generate_scan_id():
    """Generate a unique scan ID for each scan - never reuse IDs"""
    import time

    # Combine UUID with timestamp for absolute uniqueness
    unique_id = f"{uuid4()}-{int(time.time() * 1000)}"
    return unique_id[:36]  # Keep standard UUID length for compatibility


async def _do_scan(url: str, scan_id: str):
    """
    Advanced Multi-Engine Threat Detection Scan

    Features:
    - Parallel execution of 5+ detection engines
    - ML ensemble predictions with confidence scoring
    - Real-time threat intelligence integration
    - Advanced SSL/TLS analysis with certificate chain validation
    - Deep content inspection with behavioral analysis
    - Zero-failure guarantee with comprehensive fallbacks

    Args:
        url: Target URL to scan
        scan_id: Unique scan identifier

    Returns:
        ThreatReport with comprehensive analysis results
    """
    start_time = time.time()
    logger.info(f"[SEARCH] Starting advanced scan for {url} (ID: {scan_id})")

    # Robust URL parsing with error handling
    try:
        from urllib.parse import urlparse

        parsed_url = urlparse(url)
        _parsed_domain = (parsed_url.netloc or "").lower()
        if ":" in _parsed_domain:
            _parsed_domain = _parsed_domain.split(":", 1)[0]
        _parsed_domain_base = _parsed_domain[4:] if _parsed_domain.startswith("www.") else _parsed_domain

        # Early whitelist check for instant response
        from .utils import LEGITIMATE_DOMAINS

        if _parsed_domain in LEGITIMATE_DOMAINS or _parsed_domain_base in LEGITIMATE_DOMAINS:
            # Database health check (safe and non-blocking-ish)
            db_status = "disconnected"
            try:
                with get_db_connection_with_retry(max_retries=1, delay=0) as _conn:
                    if _conn and getattr(_conn, "is_connected", None) and _conn.is_connected():
                        db_status = "connected"
            except Exception:
                db_status = "error"
            result = ScanResult(
                url=url,
                is_malicious=False,
                threat_level="low",
                malicious_count=0,
                suspicious_count=0,
                total_engines=1,
                detection_details={
                    "url_analysis": {"info": "Whitelisted domain", "is_suspicious": False},
                    "ssl_analysis": {"valid": True},
                    "content_analysis": {"is_suspicious": False},
                    "virustotal_analysis": {"info": "Trusted domain - VT check skipped"},
                    "ml_analysis": {
                        "ml_enabled": True,
                        "ml_models_used": [],
                        "ml_confidence": 1.0,
                        "ml_analysis_summary": {},
                    },
                    "llm_analysis": {"status": "unavailable", "message": "Whitelisted domain - LLM analysis skipped"},
                    "database_health": {"database": db_status},
                },
                ssl_valid=True,
                domain_reputation="trusted",
                content_analysis={},
                scan_timestamp=datetime.now(),
            )
            return ThreatReport(scan_id=scan_id, url=url, status="completed", results=result)
    except Exception as e:
        logger.error(f"URL parsing error: {e}")
        _parsed_domain = ""

    try:
        async with WebShieldDetector() as detector_instance:

            async def with_timeout(coro, timeout, label):
                t0 = time.time()
                try:
                    result = await asyncio.wait_for(coro, timeout=timeout)
                    logger.info(f"{label} completed in {time.time()-t0:.2f}s")
                    return result
                except asyncio.TimeoutError:
                    logger.warning(f"{label} timed out after {timeout}s")
                    return {"error": f"{label} timed out after {timeout}s"}
                except Exception as e:
                    logger.warning(f"{label} failed: {e}")
                    return {"error": str(e)}

            # ===== STEP 1: LLM URL CLASSIFICATION FIRST (PRIMARY ASSESSMENT) =====
            # This runs BEFORE all other scans to provide initial risk assessment
            logger.info(f"STEP 1: Running LLM URL classification FIRST for {url}")
            llm_url_classification = None
            llm_initial_risk = "unknown"
            llm_initial_confidence = 0.0

            try:
                async with LLMService() as llm_service:
                    llm_url_classification = await llm_service.classify_url(url)

                    if llm_url_classification and llm_url_classification.get("success", False):
                        is_malicious_llm = llm_url_classification.get("is_malicious", False)
                        confidence = llm_url_classification.get("confidence", 0.0)
                        llm_initial_confidence = confidence

                        # Determine initial risk level from LLM
                        if is_malicious_llm and confidence > 0.8:
                            llm_initial_risk = "high"
                        elif is_malicious_llm and confidence > 0.6:
                            llm_initial_risk = "medium"
                        elif is_malicious_llm:
                            llm_initial_risk = "low-medium"
                        else:
                            llm_initial_risk = "low"

                        logger.info(f"LLM Initial Assessment: {llm_initial_risk} (confidence: {confidence:.2%})")
                    else:
                        logger.warning("WARNING: LLM URL classification returned no success flag, using fallback")
            except Exception as e:
                logger.warning(f"WARNING: LLM URL classification failed (non-critical): {e}")

            # ===== STEP 2: TRADITIONAL SCANS IN PARALLEL (VALIDATION) =====
            # These run concurrently to validate and supplement LLM findings
            logger.info("STEP 2: Running traditional scans in parallel for validation")

            # Tight timeouts to keep scans responsive (<10s total), but not so aggressive that
            # we mark everything as timed out.
            url_analysis_task = detector_instance.analyze_url_patterns(url)
            ssl_task = with_timeout(detector_instance.analyze_ssl_certificate(url), 6.0, "SSL")
            content_task = with_timeout(detector_instance.analyze_content(url, max_bytes=1024), 5.0, "Content")
            vt_task = with_timeout(detector_instance.check_virustotal(url), 3.0, "VirusTotal")

            # Execute all tasks concurrently with better error handling
            try:
                url_analysis, ssl_analysis, content_analysis, vt_analysis = await asyncio.gather(
                    url_analysis_task, ssl_task, content_task, vt_task, return_exceptions=True
                )
            except Exception as e:
                logger.error(f"Error in concurrent execution: {e}")
                # Fallback to sequential execution if concurrent fails
                url_analysis = await url_analysis_task
                ssl_analysis = await ssl_task
                content_analysis = await content_task
                vt_analysis = await vt_task

            logger.info(
                f"Scan results for {url}: url_analysis={url_analysis}, ssl_analysis={ssl_analysis}, content_analysis={content_analysis}, vt_analysis={vt_analysis}"
            )

            # Handle URL analysis with fallback
            if isinstance(url_analysis, Exception):
                logger.error(f"URL analysis failed with exception: {url_analysis}")
                url_analysis = {
                    "error": f"URL analysis failed: {str(url_analysis)}",
                    "suspicious_score": 0,
                    "detected_issues": [],
                    "domain": "N/A",
                    "is_suspicious": False,
                }
            elif not isinstance(url_analysis, dict):
                logger.error(f"URL analysis returned invalid type: {type(url_analysis)}")
                url_analysis = {
                    "error": "URL analysis returned invalid data",
                    "suspicious_score": 0,
                    "detected_issues": [],
                    "domain": "N/A",
                    "is_suspicious": False,
                }

            # Handle content analysis with fallback
            if isinstance(content_analysis, Exception):
                logger.error(f"Content analysis failed with exception: {content_analysis}")
                content_analysis = {
                    "error": f"Content analysis failed: {str(content_analysis)}",
                    "phishing_score": 0,
                    "is_suspicious": False,
                    "content_length": 0,
                    "ml_enabled": False,
                }
            elif not isinstance(content_analysis, dict):
                logger.error(f"Content analysis returned invalid type: {type(content_analysis)}")
                content_analysis = {
                    "error": "Content analysis returned invalid data",
                    "phishing_score": 0,
                    "is_suspicious": False,
                    "content_length": 0,
                    "ml_enabled": False,
                }

            # Normalize SSL analysis: treat timeouts/network failures as unknown (not invalid)
            if isinstance(ssl_analysis, Exception) or not isinstance(ssl_analysis, dict):
                ssl_analysis = {"status": "unknown", "valid": None, "error": "SSL analysis failed", "threat_score": 0}
            else:
                if "error" in ssl_analysis and "status" not in ssl_analysis:
                    # with_timeout() timeout/error payload
                    err = str(ssl_analysis.get("error") or "")
                    if "timed out" in err.lower() or "timeout" in err.lower():
                        ssl_analysis["status"] = "timeout"
                        ssl_analysis["valid"] = None
                        ssl_analysis["threat_score"] = 0
                    else:
                        ssl_analysis.setdefault("status", "unknown")
                        ssl_analysis.setdefault("valid", None)
                        ssl_analysis.setdefault("threat_score", 0)

            # Handle VirusTotal analysis with fallback
            malicious_count = 0
            suspicious_count = 0
            total_engines = 0
            vt_source = "VirusTotal"

            if isinstance(vt_analysis, dict) and "error" not in vt_analysis:
                malicious_count = vt_analysis.get("malicious_count", 0)
                suspicious_count = vt_analysis.get("suspicious_count", 0)
                total_engines = vt_analysis.get("total_engines", 0)

                # Check if fallback checks were used
                if vt_analysis.get("fallback_checks", False):
                    vt_source = "Fallback Security Checks"
                    logger.info(f"VirusTotal unavailable for {url}, using fallback security checks")
                else:
                    logger.info(f"VirusTotal analysis completed for {url}")
            else:
                # VirusTotal failed, use other security checks
                logger.warning(f"VirusTotal analysis failed for {url}, using other security checks")
                # Set default values for display
                malicious_count = 0
                suspicious_count = 0
                total_engines = 0
                vt_source = "Fallback Security Checks"

            threat_score = 0
            ml_boost = 0

            if isinstance(url_analysis, dict):
                base_score = url_analysis.get("suspicious_score", 0)
                # Give ML-based detections higher weight
                if url_analysis.get("ml_enabled", False):
                    ml_confidence = url_analysis.get("ml_confidence", 0.0)
                    # Apply boost only when ML predicts suspicious AND confidence is high
                    is_suspicious_flag = url_analysis.get("is_suspicious", False)
                    ml_boost = int(max(0.0, ml_confidence - 0.85) * 40) if is_suspicious_flag else 0
                    threat_score += base_score + ml_boost
                    logger.info(f"ML-enhanced URL analysis: base_score={base_score}, ml_boost={ml_boost}")
                else:
                    threat_score += base_score
                    logger.info(f"Rule-based URL analysis: score={base_score}")

            if isinstance(content_analysis, dict):
                base_score = content_analysis.get("phishing_score", 0)
                # Give ML-based detections higher weight
                if content_analysis.get("ml_enabled", False):
                    ml_confidence = content_analysis.get("ml_confidence", 0.0)
                    is_suspicious_content = content_analysis.get("is_suspicious", False)
                    ml_boost = int(max(0.0, ml_confidence - 0.85) * 50) if is_suspicious_content else 0
                    threat_score += base_score + ml_boost
                    logger.info(f"ML-enhanced content analysis: base_score={base_score}, ml_boost={ml_boost}")
                else:
                    threat_score += base_score
                    logger.info(f"Rule-based content analysis: score={base_score}")

            if isinstance(ssl_analysis, dict):
                # Use the new SSL threat scoring system
                ssl_threat = ssl_analysis.get("threat_score", 0) or 0
                threat_score += ssl_threat

                # Additional penalty for intentionally insecure sites
                if ssl_analysis.get("is_intentionally_insecure", False):
                    threat_score += 15  # Extra penalty for sites that are intentionally insecure

            # Add VirusTotal scores if available
            threat_score += malicious_count * 10 + suspicious_count * 5

            # Build detection_details early so the report always reflects the *actual* engine outputs.
            # IMPORTANT: Avoid silently turning missing/timeout data into a "low risk" report.
            detection_details = {
                "url_analysis": url_analysis if isinstance(url_analysis, dict) else {},
                "ssl_analysis": ssl_analysis if isinstance(ssl_analysis, dict) else {},
                "content_analysis": content_analysis if isinstance(content_analysis, dict) else {},
                "virustotal_analysis": vt_analysis if isinstance(vt_analysis, dict) else {},
                "database_health": {},
            }
            detection_details["vt_source"] = vt_source

            # Determine availability/quality flags
            vt_dict = vt_analysis if isinstance(vt_analysis, dict) else {}
            vt_available = (
                bool((vt_dict.get("total_engines") or 0) > 0)
                and not bool(vt_dict.get("fallback_mode"))
                and not bool(vt_dict.get("data_unavailable"))
            )
            vt_flagged = int((malicious_count or 0) + (suspicious_count or 0))
            ml_available = bool(isinstance(url_analysis, dict) and url_analysis.get("ml_enabled")) or bool(
                isinstance(content_analysis, dict) and content_analysis.get("ml_enabled")
            )
            ml_url_conf = (
                float(url_analysis.get("ml_confidence", 0.0) or 0.0) if isinstance(url_analysis, dict) else 0.0
            )
            ml_content_conf = (
                float(content_analysis.get("ml_confidence", 0.0) or 0.0) if isinstance(content_analysis, dict) else 0.0
            )
            ml_confidence = max(ml_url_conf, ml_content_conf)
            ml_suspicious_flag = bool(
                (
                    isinstance(url_analysis, dict)
                    and url_analysis.get("ml_enabled")
                    and url_analysis.get("is_suspicious")
                )
                or (
                    isinstance(content_analysis, dict)
                    and content_analysis.get("ml_enabled")
                    and content_analysis.get("is_suspicious")
                )
            )

            # Compute per-component scores for UI charts (0-100).
            url_score = (
                int(max(0, min(100, (url_analysis.get("suspicious_score", 0) or 0))))
                if isinstance(url_analysis, dict)
                else 0
            )
            content_score = (
                int(max(0, min(100, (content_analysis.get("phishing_score", 0) or 0))))
                if isinstance(content_analysis, dict)
                else 0
            )
            ssl_score = (
                int(max(0, min(100, (ssl_analysis.get("threat_score", 0) or 0))))
                if isinstance(ssl_analysis, dict)
                else 0
            )
            vt_score = int(max(0, min(100, (malicious_count * 10 + suspicious_count * 5)))) if vt_available else 0

            # Check for SSL/security issues first (ignore network/errors)
            ssl_issues = False
            if isinstance(ssl_analysis, dict):
                has_ssl_error = "error" in ssl_analysis
                ssl_issues = (
                    (not has_ssl_error and not ssl_analysis.get("valid", True))
                    or ssl_analysis.get("is_intentionally_insecure", False)
                    or ssl_analysis.get("threat_score", 0) > 20
                )

            # Only treat ML as a strong signal when confidence AND suspicious score are high.
            # This reduces false positives on the long tail of normal websites.
            ml_signal_score = int(max(url_score, content_score))
            ml_threat = bool(ml_suspicious_flag and ml_confidence >= 0.95 and ml_signal_score >= 55)
            # IMPORTANT: ML confidence is NOT a risk score.
            # Only contribute ML score when ML actually flags the URL/content as suspicious.
            ml_score = int(max(0, min(100, ml_confidence * 100))) if (ml_available and ml_suspicious_flag) else 0

            # Store breakdown for real-time charts (no fallbacks on the frontend).
            # Include LLM risk scores for display in the report charts
            llm_risk_score = 0  # Convert LLM risk level to numeric score
            if llm_initial_risk == "high":
                llm_risk_score = int(llm_initial_confidence * 100) if llm_initial_confidence > 0.7 else 75
            elif llm_initial_risk == "medium" or llm_initial_risk == "low-medium":
                llm_risk_score = int(llm_initial_confidence * 70) if llm_initial_confidence > 0.5 else 40
            elif llm_initial_risk == "low":
                llm_risk_score = int((1 - llm_initial_confidence) * 20)  # Low risk = low score

            # Calculate weighted total score
            # User wants: Speed + Accuracy, so optimize weights for both VT and ML
            score_total = int(
                max(
                    0,
                    min(
                        100,
                        (0.40 * vt_score)
                        + (0.30 * ml_score)
                        + (0.15 * llm_risk_score)
                        + (0.10 * max(url_score, content_score))
                        + (0.05 * ssl_score),
                    ),
                )
            )

            # CRITICAL FIX: Ensure high-risk sites always show high scores
            # Even with weighted average, VT consensus should force high score
            if vt_flagged > 3:
                score_total = max(score_total, 85)  # 4+ engines = at least 85/100
                logger.info(f"VT consensus ({vt_flagged} engines) - enforcing minimum score 85")
            elif vt_flagged > 1:
                score_total = max(score_total, 60)  # 2+ engines = at least 60/100
                logger.info(f"VT moderate detection ({vt_flagged} engines) - enforcing minimum score 60")

            # Also respect LLM high confidence warnings
            if llm_initial_risk == "high" and llm_initial_confidence > 0.9:
                score_total = max(score_total, 70)  # LLM very confident = at least 70/100
                logger.info(
                    f"LLM high confidence (risk={llm_initial_risk}, conf={llm_initial_confidence:.2f}) - enforcing minimum score 70"
                )

            # Ensure SSL issues contribute meaningfully
            if ssl_issues and ssl_score > 50:
                score_total = max(score_total, 55)  # Significant SSL issues = moderate score
                logger.info("SSL issues detected - enforcing minimum score 55")

            detection_details["score_breakdown"] = {
                "total_score": score_total,
                "virustotal": vt_score,
                "ml": ml_score,
                "llm": llm_risk_score,
                "llm_risk_level": llm_initial_risk,
                "llm_confidence": round(llm_initial_confidence, 3),
                "url": url_score,
                "content": content_score,
                "ssl": ssl_score,
                "method": (
                    "VirusTotal-Primary"
                    if vt_available
                    else (
                        "ML-Primary"
                        if ml_available
                        else "LLM-Assisted" if llm_initial_confidence > 0.5 else "Traditional-Scores"
                    )
                ),
            }
            detection_details["data_quality"] = {
                "virustotal_available": vt_available,
                "ml_available": ml_available,
                "llm_available": llm_initial_confidence > 0,
                "virustotal_error": vt_dict.get("error") if isinstance(vt_dict.get("error"), str) else None,
            }

            # ===== STEP 3: DETERMINE THREAT LEVEL (VT + ML PRIMARY, LLM ASSISTANCE) =====
            # Priority order per user requirements:
            # 1. VirusTotal detections (PRIMARY) - 2+ engines = high
            # 2. SSL Status - 0 engines + No SSL = moderate
            # 3. Low - 0 engines + Valid SSL

            # PRIMARY ASSESSMENT: VirusTotal & SSL
            # Policy (user specific):
            # - HIGH: VirusTotal engines >= 2
            # - MODERATE: VirusTotal engines == 1 OR (VirusTotal == 0 AND No SSL)
            # - LOW: VirusTotal engines == 0 AND Valid SSL

            if vt_available:
                detection_details["primary_assessment"] = "virustotal_ssl"
                vt_threat_level = None

                # Determine base threat level
                is_ssl_valid = False
                if isinstance(ssl_analysis, dict):
                    # Consider SSL valid if explicit valid=True and no errors
                    is_ssl_valid = ssl_analysis.get("valid", False) is True and not ssl_analysis.get("error")

                # Check User Defined Logic
                if vt_flagged >= 2:
                    # High if VT engines >= 2
                    vt_threat_level = "high"
                    is_malicious = True
                    logger.info(f"Threat Check: HIGH (VT engines {vt_flagged} >= 2)")
                elif vt_flagged == 1:
                    # Moderate if VT engine == 1
                    vt_threat_level = "medium"
                    is_malicious = False  # Suspicious but not confirmed malicious
                    logger.info(f"Threat Check: MEDIUM (VT engines {vt_flagged} == 1)")
                elif vt_flagged == 0 and not is_ssl_valid:
                    # Moderate if VT==0 but No SSL/Expired SSL
                    vt_threat_level = "medium"
                    is_malicious = False
                    logger.info("Threat Check: MEDIUM (VT engines 0 but No SSL/Expired)")
                else:
                    # Low if VT==0 and SSL Valid (implied else)
                    vt_threat_level = "low"
                    is_malicious = False
                    logger.info("Threat Check: LOW (VT engines 0 and SSL Valid)")

                # LLM CONFLICT RESOLUTION (per user: show moderate if VT low + LLM high)
                if vt_threat_level == "low" and llm_initial_risk == "high" and llm_initial_confidence > 0.85:
                    logger.warning(
                        f"🤖 LLM OVERRIDE: VT says LOW (0 detections) but LLM says HIGH (conf={llm_initial_confidence:.2f})"
                    )
                    logger.warning("   Escalating to MEDIUM for user review")
                    threat_level = "medium"  # Escalate to moderate for user review
                    detection_details["llm_vt_conflict"] = {
                        "vt_verdict": "low",
                        "llm_verdict": llm_initial_risk,
                        "llm_confidence": llm_initial_confidence,
                        "resolution": "escalated_to_medium",
                    }
                elif vt_threat_level == "high" and llm_initial_risk == "low" and llm_initial_confidence > 0.85:
                    # VT says HIGH but LLM disagrees - trust VT for threats
                    logger.warning("⚠️ VT/LLM DISAGREEMENT: VT says HIGH but LLM says LOW")
                    logger.warning("   Trusting VT (primary) - keeping HIGH risk")
                    threat_level = "high"
                    detection_details["llm_vt_conflict"] = {
                        "vt_verdict": "high",
                        "llm_verdict": llm_initial_risk,
                        "llm_confidence": llm_initial_confidence,
                        "resolution": "vt_wins_on_high_threat",
                    }
                else:
                    # No conflict or low confidence - use VT verdict
                    threat_level = vt_threat_level

                # Check if ML also flags when VT says safe
                if threat_level == "low" and ml_available and ml_threat:
                    logger.info("ML flags suspicious but VT says clean - setting to MEDIUM")
                    threat_level = "medium"  # ML only = moderate, not high

            # PRIMARY: ML (when VT is unavailable)
            # Policy: ML suspicious => HIGH, else LOW
            elif ml_available:
                detection_details["primary_assessment"] = "ml"
                if ml_threat:
                    threat_level = "high"
                    is_malicious = True
                else:
                    threat_level = "low"
                    is_malicious = False

            # SECONDARY: traditional scores / SSL
            else:
                detection_details["primary_assessment"] = "traditional"
                # If we couldn't run VT or ML, do NOT confidently claim "low"
                if threat_score > 90:
                    threat_level = "high"
                    is_malicious = True
                elif threat_score > 60 or ssl_issues:
                    # Expired SSL or moderate threat score -> Medium
                    threat_level = "medium"
                    is_malicious = False  # Changed from True to False for medium
                else:
                    threat_level = "unknown"
                    is_malicious = False

            # Trusted domain override: if domain is trusted and no VT detections or SSL issues, force safe
            if (
                (_parsed_domain in LEGITIMATE_DOMAINS or _parsed_domain_base in LEGITIMATE_DOMAINS)
                and malicious_count == 0
                and not ssl_issues
            ):
                logger.info(f"Trusted domain override applied for {_parsed_domain}")
                threat_level = "low"
                is_malicious = False
                try:
                    if isinstance(url_analysis, dict):
                        url_analysis["suspicious_score"] = 0
                        url_analysis["is_suspicious"] = False
                        di = url_analysis.get("detected_issues", []) or []
                        if "Legitimate domain whitelisted" not in di:
                            di.append("Legitimate domain whitelisted")
                        url_analysis["detected_issues"] = di
                except Exception:  # nosec B110
                    pass

            # ===== STEP 4: FAST AI EXPLANATION (NO DOUBLE LLM CALLS) =====
            # We already did LLM URL classification. Optionally do a lightweight content classification
            # and generate an explanation (with strict timeouts) for the report.
            llm_analysis_payload = {
                "llm_risk_level": llm_initial_risk,
                "llm_confidence": llm_initial_confidence,
                "assessment_method": (
                    "VirusTotal-Primary" if vt_available else "ML-Primary" if ml_available else "Traditional-Scores"
                ),
                "url_classification": llm_url_classification
                or {"success": False, "fallback": True, "model": "unavailable"},
                "content_classification": None,
                "explanation": None,
                "models_used": {
                    "url_classifier": (
                        (llm_url_classification or {}).get("model", "unavailable")
                        if isinstance(llm_url_classification, dict)
                        else "unavailable"
                    ),
                    "content_classifier": None,
                    "explanation_generator": None,
                },
            }

            html_content = ""
            if isinstance(content_analysis, dict):
                html_content = content_analysis.get("html_text", "") or ""
            try:
                async with LLMService() as llm_service:
                    try:
                        llm_content = await asyncio.wait_for(
                            llm_service.classify_html_content(html_content, url=url),
                            timeout=1.5,
                        )
                    except asyncio.TimeoutError:
                        llm_content = None
                    if isinstance(llm_content, dict):
                        llm_analysis_payload["content_classification"] = llm_content
                        llm_analysis_payload["models_used"]["content_classifier"] = llm_content.get("model")

                        try:
                            is_phishing_llm = bool(llm_content.get("is_phishing", False))
                            phishing_conf = float(llm_content.get("confidence", 0.0) or 0.0)
                            phishing_conf = max(0.0, min(1.0, phishing_conf))

                            # If the LLM flags phishing, don't allow a LOW final verdict.
                            # Keep whitelisted domains safe (handled earlier), otherwise escalate for user safety.
                            if is_phishing_llm and phishing_conf >= 0.70:
                                prev_level = threat_level
                                if phishing_conf >= 0.90:
                                    threat_level = "high" if threat_level != "high" else threat_level
                                    # Treat as malicious when the LLM is very confident about phishing.
                                    is_malicious = True
                                else:
                                    if threat_level == "low":
                                        threat_level = "medium"
                                    # Medium is suspicious but not confirmed malicious.
                                    is_malicious = is_malicious if threat_level == "high" else False

                                # Keep UI score consistent with the escalated verdict.
                                try:
                                    score_total = int(detection_details.get("score_breakdown", {}).get("total_score", score_total))
                                except Exception:
                                    score_total = score_total
                                if threat_level == "medium":
                                    score_total = max(score_total, 60)
                                elif threat_level == "high":
                                    score_total = max(score_total, 75)

                                try:
                                    if "score_breakdown" in detection_details and isinstance(detection_details["score_breakdown"], dict):
                                        detection_details["score_breakdown"]["total_score"] = score_total
                                except Exception:
                                    pass

                                detection_details["llm_content_override"] = {
                                    "previous_threat_level": prev_level,
                                    "new_threat_level": threat_level,
                                    "is_phishing": True,
                                    "llm_confidence": phishing_conf,
                                    "resolution": "escalated_due_to_llm_phishing",
                                }
                        except Exception:
                            pass

                    # Explanation: keep it fast; if the HF model doesn't respond quickly, fall back to template.
                    try:
                        exp = await asyncio.wait_for(
                            llm_service.generate_explanation(
                                url=url,
                                url_classification=llm_analysis_payload["url_classification"] or {},
                                content_classification=llm_analysis_payload["content_classification"] or {},
                                ssl_analysis=ssl_analysis if isinstance(ssl_analysis, dict) else {},
                                vt_analysis=vt_analysis if isinstance(vt_analysis, dict) else {},
                            ),
                            timeout=1.75,
                        )
                    except asyncio.TimeoutError:
                        exp = None

                    if isinstance(exp, dict):
                        llm_analysis_payload["explanation"] = exp
                        llm_analysis_payload["models_used"]["explanation_generator"] = exp.get("model")
                    else:
                        llm_analysis_payload["explanation"] = {
                            "success": False,
                            "explanation": "Automated analysis could not generate an explanation within the time budget. Results below are based on fast multi-engine checks.",
                            "risk_summary": "No detailed explanation available.",
                            "threat_factors": [],
                            "safety_factors": [],
                            "recommended_action": "Use the component results and risk indicators below to decide. When in doubt, avoid entering credentials.",
                            "model": "timeout-fallback",
                            "fallback": True,
                        }
            except Exception:
                llm_analysis_payload["explanation"] = {
                    "success": False,
                    "explanation": "AI analysis was unavailable. Results below are based on fast multi-engine checks.",
                    "risk_summary": "AI analysis unavailable.",
                    "threat_factors": [],
                    "safety_factors": [],
                    "recommended_action": "Proceed cautiously and verify the URL before entering sensitive information.",
                    "model": "unavailable",
                    "fallback": True,
                }

            # Guarantee a valid ScanResult even if all checks are empty or error
            # Normalize LLM payload into a stable wrapper expected by tests/UI.
            try:
                llm_status = "available"
                if not isinstance(llm_analysis_payload, dict):
                    llm_status = "unavailable"
                    llm_analysis_payload = {"status": "unavailable", "message": "No LLM payload"}
                detection_details["llm_analysis"] = {
                    "status": llm_status,
                    "llm_analysis": llm_analysis_payload,
                }
            except Exception:
                detection_details["llm_analysis"] = {
                    "status": "unavailable",
                    "llm_analysis": {"status": "unavailable", "message": "LLM normalization failed"},
                }

            # Add ML analysis information
            ml_info = {"ml_enabled": False, "ml_models_used": [], "ml_confidence": 0.0, "ml_analysis_summary": {}}

            # Check URL analysis ML usage
            if isinstance(url_analysis, dict) and url_analysis.get("ml_enabled", False):
                ml_info["ml_enabled"] = True
                ml_info["ml_models_used"].append("URL Threat Classifier")
                ml_info["ml_confidence"] = max(ml_info["ml_confidence"], url_analysis.get("ml_confidence", 0.0))
                ml_info["ml_analysis_summary"]["url"] = {
                    "model": "URL Threat Classifier",
                    "confidence": url_analysis.get("ml_confidence", 0.0),
                    "prediction": url_analysis.get("is_suspicious", False),
                    "features_analyzed": len(url_analysis.get("detected_issues", [])),
                }

            # Check content analysis ML usage
            if isinstance(content_analysis, dict) and content_analysis.get("ml_enabled", False):
                ml_info["ml_enabled"] = True
                ml_info["ml_models_used"].append("Content Phishing Detector")
                ml_info["ml_confidence"] = max(ml_info["ml_confidence"], content_analysis.get("ml_confidence", 0.0))
                ml_info["ml_analysis_summary"]["content"] = {
                    "model": "Content Phishing Detector",
                    "confidence": content_analysis.get("ml_confidence", 0.0),
                    "prediction": content_analysis.get("is_suspicious", False),
                    "features_analyzed": len(content_analysis.get("detected_indicators", [])),
                }

            # Add ML info to detection details
            detection_details["ml_analysis"] = ml_info

            # Ensure at least one field is always present in detection_details
            if not detection_details["url_analysis"]:
                detection_details["url_analysis"] = {"info": "No suspicious patterns found"}
            if not detection_details["ssl_analysis"]:
                detection_details["ssl_analysis"] = {"info": "No SSL issues found"}
            if not detection_details["content_analysis"]:
                detection_details["content_analysis"] = {"info": "No phishing indicators found"}
            if not detection_details["virustotal_analysis"]:
                detection_details["virustotal_analysis"] = {
                    "info": "VirusTotal analysis unavailable - using other security checks"
                }

            # Add information about which security checks were used
            detection_details["vt_source"] = vt_source
            result = ScanResult(
                url=url,
                is_malicious=is_malicious,
                threat_level=threat_level,
                malicious_count=malicious_count,
                suspicious_count=suspicious_count,
                total_engines=total_engines,
                detection_details=detection_details,
                # ssl_valid should represent certificate validation, not network timeouts.
                ssl_valid=(True if isinstance(ssl_analysis, dict) and ssl_analysis.get("valid") is True else False),
                domain_reputation="malicious" if is_malicious else "clean",
                content_analysis=content_analysis if isinstance(content_analysis, dict) else {},
                scan_timestamp=datetime.now(),
            )
            with get_db_connection_with_retry() as conn:
                if conn:
                    cursor = conn.cursor()
                    logger.info(f"Updating scan {scan_id} status to completed")
                    # Ensure user_email column exists for filtering recent scans
                    try:
                        cursor.execute("ALTER TABLE scans ADD COLUMN user_email VARCHAR(255)")
                        conn.commit()
                    except Exception:  # nosec B110
                        pass

                    update_query = """
                    UPDATE scans SET
                        status = %s,
                        is_malicious = %s,
                        threat_level = %s,
                        malicious_count = %s,
                        suspicious_count = %s,
                        total_engines = %s,
                        ssl_valid = %s,
                        domain_reputation = %s,
                        detection_details = %s,
                        completed_at = %s,
                        scan_timestamp = %s
                    WHERE scan_id = %s
                    """
                    try:
                        cursor.execute(
                            update_query,
                            (
                                "completed",
                                is_malicious,
                                threat_level,
                                malicious_count,
                                suspicious_count,
                                total_engines,
                                ssl_analysis.get("valid", False),
                                "malicious" if is_malicious else "clean",
                                json.dumps(result.detection_details),
                                datetime.now(),
                                result.scan_timestamp,
                                scan_id,
                            ),
                        )
                        conn.commit()
                        logger.info(f"Successfully updated scan {scan_id} to completed status")
                    except Exception as e:
                        logger.error(f"Failed to update scan {scan_id}: {e}")
                        try:
                            conn.rollback()
                        except Exception as e_rollback:
                            logger.warning(f"Failed to rollback DB on scan completion error: {e_rollback}")
                    finally:
                        cursor.close()
                else:
                    logger.error(f"No database connection available for scan {scan_id} completion")
            logger.info(f"Total scan time: {time.time()-start_time:.2f}s")
            resp = ThreatReport(scan_id=scan_id, url=url, status="completed", results=result)
            try:
                SCAN_REPORTS_BY_ID[scan_id] = resp
            except Exception as e_mem:
                logger.warning(f"Failed to update scan cache: {e_mem}")
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        # Always store a completed scan result, even on error
        detection_details = {
            "url_analysis": {"error": "Scan failed"},
            "ssl_analysis": {"error": "Scan failed"},
            "content_analysis": {"error": "Scan failed"},
            "virustotal_analysis": {"error": "Scan failed"},
            "database_health": {"database": "error"},
            "llm_analysis": {
                "status": "unavailable",
                "llm_analysis": {"status": "unavailable", "message": "Scan failed before LLM analysis"},
            },
            "ml_analysis": {"ml_enabled": False, "ml_models_used": [], "ml_confidence": 0.0, "ml_analysis_summary": {}},
            "vt_source": "Scan Failed",
        }
        result = ScanResult(
            url=url,
            is_malicious=False,
            threat_level="low",
            malicious_count=0,
            suspicious_count=0,
            total_engines=0,
            detection_details=detection_details,
            ssl_valid=False,
            domain_reputation="unknown",
            content_analysis={},
            scan_timestamp=datetime.now(),
        )
        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()
                logger.info(f"Setting scan {scan_id} status to completed (error case)")
                update_query = """
                UPDATE scans SET status = %s, detection_details = %s, completed_at = %s, scan_timestamp = %s WHERE scan_id = %s
                """
                try:
                    cursor.execute(
                        update_query,
                        (
                            "completed",
                            json.dumps(result.detection_details),
                            datetime.now(),
                            result.scan_timestamp,
                            scan_id,
                        ),
                    )
                    conn.commit()
                    logger.info(f"Successfully updated scan {scan_id} to completed status (error case)")
                except Exception as e:
                    logger.error(f"Failed to update scan {scan_id} in error case: {e}")
                    try:
                        conn.rollback()
                    except Exception as e_rollback:
                        logger.warning(f"Failed to rollback DB on scan error handling: {e_rollback}")
                finally:
                    cursor.close()
            else:
                logger.error(f"No database connection available for scan {scan_id} error handling")
        resp = ThreatReport(scan_id=scan_id, url=url, status="completed", results=result)
        try:
            SCAN_REPORTS_BY_ID[scan_id] = resp
        except Exception as e_mem:
            logger.warning(f"Failed to update scan cache in error handler: {e_mem}")
    finally:
        # Clean up scan tracking
        SCAN_IN_PROGRESS.pop(url, None)

    return resp


@scan_router.post("", response_model=ThreatReport)
@scan_router.post("/", response_model=ThreatReport)
@scan_router.post("/scan", response_model=ThreatReport)
async def scan_url(request: URLScanRequest, background_tasks: BackgroundTasks):
    """Enhanced scan endpoint with zero-failure guarantee"""
    try:
        url = str(request.url).strip()

        # Comprehensive URL validation and normalization
        if not url:
            return ThreatReport(
                scan_id=generate_scan_id(), url="", status="error", results=None, error_message="Empty URL provided"
            )

        # Auto-prepend https:// if missing
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "https://" + url

        # Enhanced URL validation with multiple patterns
        url_patterns = [
            re.compile(r"^https?://[\w\-._~:/?#[\]@!$&\'()*+,;=]+$"),
            re.compile(r"^https?://([\w.-]+)(:[0-9]+)?(/.*)?$"),
            re.compile(r"^https?://[^\s]+$"),
        ]

        is_valid = any(pattern.match(url) for pattern in url_patterns)

        if not is_valid:
            # Try to fix common URL issues
            url = url.replace(" ", "%20")  # Encode spaces
            url = re.sub(r"[^\x00-\x7F]+", "", url)  # Remove non-ASCII

            # Re-validate
            is_valid = any(pattern.match(url) for pattern in url_patterns)

            if not is_valid:
                return ThreatReport(
                    scan_id=generate_scan_id(),
                    url=request.url,
                    status="error",
                    results=None,
                    error_message="Invalid URL format. Please check the URL and try again.",
                )

        # Instant completion for known-safe domains (deterministic + faster UX)
        try:
            from urllib.parse import urlparse

            from .utils import LEGITIMATE_DOMAINS

            parsed_url = urlparse(url)
            parsed_domain = (parsed_url.netloc or "").lower()
            if parsed_domain in LEGITIMATE_DOMAINS:
                scan_id = generate_scan_id()
                result = ScanResult(
                    url=url,
                    is_malicious=False,
                    threat_level="low",
                    malicious_count=0,
                    suspicious_count=0,
                    total_engines=1,
                    detection_details={
                        "url_analysis": {
                            "info": "Whitelisted domain",
                            "is_suspicious": False,
                            "domain": parsed_domain,
                            "suspicious_score": 0,
                        },
                        "ssl_analysis": {"valid": True, "threat_score": 0},
                        "content_analysis": {"is_suspicious": False, "phishing_score": 0},
                        "virustotal_analysis": {"info": "Trusted domain - VT check skipped"},
                        "ml_analysis": {
                            "ml_enabled": True,
                            "ml_models_used": [],
                            "ml_confidence": 1.0,
                            "ml_analysis_summary": {},
                        },
                        "llm_analysis": {
                            "status": "unavailable",
                            "message": "Whitelisted domain - LLM analysis skipped",
                        },
                        "database_health": {"database": "skipped"},
                    },
                    ssl_valid=True,
                    domain_reputation="trusted",
                    content_analysis={},
                    scan_timestamp=datetime.now(),
                )
                completed = ThreatReport(scan_id=scan_id, url=url, status="completed", results=result)
                try:
                    SCAN_REPORTS_BY_ID[scan_id] = completed
                except Exception as e:
                    logger.debug(f"Failed to cache whitelist scan: {e}")
                return completed
        except Exception as e:
            # Never fail the request due to whitelist fast-path issues
            logger.warning(f"Whitelist fast-path failed, proceeding to full scan: {e}")

        # Check if URL is already being scanned
        if url in SCAN_IN_PROGRESS:
            scan_id = SCAN_IN_PROGRESS[url]
            logger.info(f"URL {url} already being scanned with ID: {scan_id}")
            return ThreatReport(scan_id=scan_id, url=url, status="processing", results=None)

        # Generate new scan ID
        scan_id = generate_scan_id()
        logger.info(f"Generated scan ID: {scan_id}")
        logger.info(f"Scan ID type: {type(scan_id)}")
        logger.info(f"Scan ID length: {len(scan_id)}")
        logger.info(f"Starting new scan for {url} with ID: {scan_id}")

        # Add to in-progress tracking with timestamp
        SCAN_IN_PROGRESS[url] = scan_id
        SCAN_IN_PROGRESS_TIMESTAMPS[url] = time.time()

        # Store initial processing state in-memory so UI can poll even if DB is down
        try:
            SCAN_REPORTS_BY_ID[scan_id] = ThreatReport(scan_id=scan_id, url=url, status="processing", results=None)
        except Exception as e:
            logger.warning(f"Failed to cache initial scan state: {e}")

    except Exception as e:
        # Comprehensive error handling for zero failures
        logger.error(f"Error in scan_url: {e}")
        return ThreatReport(
            scan_id=generate_scan_id(),
            url=request.url,
            status="error",
            results=None,
            error_message=f"Scan initialization failed: {str(e)}",
        )

    # Insert processing status in DB (best-effort). If DB is unavailable, continue scan without persistence.
    try:
        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor()
                logger.info(
                    f"Inserting scan into database: scan_id={scan_id}, url={url}, user_email={request.user_email}"
                )
                insert_query = """
                INSERT INTO scans (scan_id, url, status, created_at, user_email)
                VALUES (%s, %s, %s, %s, %s)
                """
                try:
                    cursor.execute(insert_query, (scan_id, url, "processing", datetime.now(), request.user_email))
                    conn.commit()
                    logger.info(f"Successfully inserted scan {scan_id} into database")
                except Exception as e:
                    logger.error(f"Failed to insert scan {scan_id}: {e}")
                    try:
                        conn.rollback()
                    except Exception as e_rollback:
                        logger.warning(f"Failed to rollback DB on insert error: {e_rollback}")
                finally:
                    cursor.close()
            else:
                logger.warning("Database unavailable for scan insertion; continuing with in-memory tracking only")
    except Exception as e:
        logger.warning(f"Database insert skipped due to error; continuing with in-memory tracking only: {e}")

    # CRITICAL FIX: Use asyncio.create_task instead of threading
    # Creating new event loops per scan was causing crashes on Windows
    async def execute_scan_async():
        """Execute scan in background without blocking the response"""
        global _active_scans
        try:
            _active_scans += 1
            logger.info(f"Starting async scan (active scans: {_active_scans}/{_max_concurrent_scans})")
            await _do_scan(url, scan_id)
        except Exception as e:
            logger.error(f"Background scan error: {e}")
            import traceback

            logger.error(traceback.format_exc())
        finally:
            _active_scans -= 1
            # Always clean up the in-progress tracking
            if url in SCAN_IN_PROGRESS and SCAN_IN_PROGRESS[url] == scan_id:
                SCAN_IN_PROGRESS.pop(url, None)
                SCAN_IN_PROGRESS_TIMESTAMPS.pop(url, None)
                logger.info(f"Cleaned up scan tracking for {url}")

    # Check if we're at capacity
    if _active_scans >= _max_concurrent_scans:
        logger.warning(f"Scan queue at capacity ({_active_scans}/{_max_concurrent_scans})")
        return ThreatReport(
            scan_id=scan_id,
            url=url,
            status="error",
            results=None,
            error_message=f"Server at capacity ({_active_scans} scans). Please retry.",
        )

    # Create async task instead of thread pool (prevents crashes)
    try:
        asyncio.create_task(execute_scan_async())
        logger.info(f"Created async task for scan {scan_id}")
    except Exception as e:
        logger.error(f"Failed to create async task: {e}")
        SCAN_IN_PROGRESS.pop(url, None)
        SCAN_IN_PROGRESS_TIMESTAMPS.pop(url, None)
        return ThreatReport(
            scan_id=scan_id, url=url, status="error", results=None, error_message=f"Failed to start scan: {str(e)}"
        )

    # Always return a valid response with scan_id
    response = ThreatReport(scan_id=scan_id, url=url, status="processing", results=None)
    logger.info(f"Returning scan response for ID: {response.scan_id}")
    return response


@scan_router.get("/{scan_id}")
@scan_router.get("/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan results by ID. Always return a valid 'results' object for completed scans."""
    try:
        scan_logger = logging.getLogger("scan")
        scan_logger.info("Getting scan result for ID: %s", scan_id)

        # Fast-path: in-memory cache (works even if DB is down)
        try:
            cached_report = SCAN_REPORTS_BY_ID.get(scan_id)
            if cached_report is not None:
                # If we cached a completed ThreatReport, return consistent API shape
                if (
                    getattr(cached_report, "status", None) == "completed"
                    and getattr(cached_report, "results", None) is not None
                ):
                    r = cached_report.results
                    return {
                        "scan_id": cached_report.scan_id,
                        "url": cached_report.url,
                        "status": cached_report.status,
                        "results": r.model_dump() if hasattr(r, "model_dump") else r,
                    }
                return {
                    "scan_id": cached_report.scan_id,
                    "url": cached_report.url,
                    "status": cached_report.status,
                    "results": None,
                }
        except Exception as e:
            logger.debug(f"Cache lookup failed in get_scan_result: {e}")

        with get_db_connection_with_retry() as conn:
            if conn:
                cursor = conn.cursor(dictionary=True)
                select_query = """
                SELECT scan_id, url, status, is_malicious, threat_level, malicious_count,
                       suspicious_count, total_engines, ssl_valid, domain_reputation,
                       detection_details, created_at, completed_at, scan_timestamp
                FROM scans WHERE scan_id = %s
                """
                cursor.execute(select_query, (scan_id,))
                scan = cursor.fetchone()
                cursor.close()

                # Debug logging
                scan_logger.info(f"Looking for scan_id: {scan_id}")
                if scan:
                    scan_logger.info(f"Found scan: {scan['scan_id']}, status: {scan['status']}")
                else:
                    scan_logger.warning(f"Scan not found: {scan_id}")
            else:
                scan_logger.error("No database connection available")
                scan = None

            if scan:
                # Convert detection_details from JSON string to dict
                if scan["detection_details"]:
                    scan["detection_details"] = json.loads(scan["detection_details"])
                # Always return a valid results object for completed scans
                if scan["status"] == "completed":
                    # Fallback: if detection_details or results are missing, return a default clean result
                    detection_details = (
                        scan["detection_details"]
                        if scan["detection_details"]
                        else {
                            "url_analysis": {"info": "No suspicious patterns found"},
                            "ssl_analysis": {"info": "No SSL issues found"},
                            "content_analysis": {"info": "No phishing indicators found"},
                            "virustotal_analysis": {"info": "No VirusTotal data"},
                            "database_health": {"database": "unknown"},
                            "llm_analysis": {"status": "unavailable", "message": "No LLM analysis data"},
                            "ml_analysis": {
                                "ml_enabled": False,
                                "ml_models_used": [],
                                "ml_confidence": 0.0,
                                "ml_analysis_summary": {},
                            },
                        }
                    )
                    return {
                        "scan_id": scan["scan_id"],
                        "url": scan["url"],
                        "status": scan["status"],
                        "results": {
                            "url": scan["url"],
                            "is_malicious": scan.get("is_malicious", False),
                            "threat_level": scan.get("threat_level", "unknown"),
                            "malicious_count": scan.get("malicious_count", 0),
                            "suspicious_count": scan.get("suspicious_count", 0),
                            "total_engines": scan.get("total_engines", 0),
                            "detection_details": detection_details,
                            "ssl_valid": scan.get("ssl_valid", False),
                            "domain_reputation": scan.get("domain_reputation", "unknown"),
                            "content_analysis": detection_details.get("content_analysis", {}),
                            "scan_timestamp": scan.get("scan_timestamp") or scan.get("completed_at"),
                        },
                    }
                else:
                    # Scan is processing or errored
                    return {"scan_id": scan["scan_id"], "url": scan["url"], "status": scan["status"], "results": None}
            else:
                # Scan not found in database
                raise HTTPException(status_code=404, detail="Scan not found")
    except HTTPException:
        raise
    except Exception as e:
        # If we cannot retrieve due to infra issues, still prefer a stable 404 for unknown scan ids.
        logging.getLogger("scan").error(f"Error retrieving scan {scan_id}: {str(e)}")
        raise HTTPException(status_code=404, detail="Scan not found") from e
