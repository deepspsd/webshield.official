# -*- coding: utf-8 -*-
"""
LLM Service for WebShield - Advanced Threat Analysis (Groq)

This module provides:
1. URL Classification (Groq)
2. HTML Content Classification (Groq)
3. Explanation Generation (Groq)
4. Fast local fallbacks when Groq is not configured or times out
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

# Groq API Configuration (OpenAI-compatible)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_API_BASE = os.getenv("GROQ_API_BASE", "https://api.groq.com/openai/v1")
GROQ_EXPLANATION_MODEL = os.getenv("GROQ_EXPLANATION_MODEL", "llama-3.1-8b-instant")
GROQ_REQUEST_TIMEOUT_SECONDS = float(os.getenv("GROQ_REQUEST_TIMEOUT_SECONDS", "5.0"))
GROQ_MAX_RETRIES = int(os.getenv("GROQ_MAX_RETRIES", "2"))
GROQ_RETRY_DELAY = float(os.getenv("GROQ_RETRY_DELAY", "0.5"))


class LLMService:
    """Advanced LLM Service for threat detection and explanation"""

    def __init__(self):
        self.session = None
        self.api_key = GROQ_API_KEY
        # Keep time budget tight so scans remain responsive.
        self.timeout = aiohttp.ClientTimeout(total=max(3, int(GROQ_REQUEST_TIMEOUT_SECONDS) + 1))

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def _query_groq_chat(
        self,
        messages: List[Dict[str, str]],
        model: str = GROQ_EXPLANATION_MODEL,
        temperature: float = 0.3,
        max_tokens: int = 240,
        request_timeout_seconds: float = GROQ_REQUEST_TIMEOUT_SECONDS,
    ) -> Optional[str]:
        """Query Groq chat completions (OpenAI-compatible) and return assistant text.

        Includes retry logic: up to GROQ_MAX_RETRIES retries with exponential
        backoff for transient failures (timeouts and 5xx server errors).
        """
        if not GROQ_API_KEY:
            return None

        if not self.session:
            self.session = aiohttp.ClientSession(timeout=self.timeout)

        url = f"{GROQ_API_BASE.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        last_error: Optional[str] = None
        for attempt in range(1 + GROQ_MAX_RETRIES):
            try:
                async with asyncio.timeout(request_timeout_seconds):
                    async with self.session.post(url, headers=headers, json=payload) as response:
                        # Retry on 5xx server errors
                        if response.status >= 500:
                            try:
                                error_text = await response.text()
                            except Exception:
                                error_text = ""
                            last_error = f"Groq API server error {response.status}: {error_text[:200]}"
                            logger.warning(f"{last_error} (attempt {attempt + 1}/{1 + GROQ_MAX_RETRIES})")
                            if attempt < GROQ_MAX_RETRIES:
                                await asyncio.sleep(GROQ_RETRY_DELAY * (2 ** attempt))
                                continue
                            return None

                        if response.status != 200:
                            try:
                                error_text = await response.text()
                            except Exception:
                                error_text = ""
                            logger.warning(f"Groq API error {response.status}: {error_text[:200]}")
                            return None

                        data = await response.json()
                        if not isinstance(data, dict):
                            return None
                        choices = data.get("choices")
                        if not isinstance(choices, list) or not choices:
                            return None
                        message = choices[0].get("message") if isinstance(choices[0], dict) else None
                        content = message.get("content") if isinstance(message, dict) else None
                        if isinstance(content, str) and content.strip():
                            return content.strip()
                        return None
            except (TimeoutError, asyncio.TimeoutError):
                last_error = f"Groq request timed out after {request_timeout_seconds}s"
                logger.warning(f"{last_error} (attempt {attempt + 1}/{1 + GROQ_MAX_RETRIES})")
                if attempt < GROQ_MAX_RETRIES:
                    await asyncio.sleep(GROQ_RETRY_DELAY * (2 ** attempt))
                    continue
            except Exception as e:
                logger.warning(f"Groq request failed: {e}")
                return None

        logger.warning(f"Groq request failed after {1 + GROQ_MAX_RETRIES} attempts: {last_error}")
        return None

    async def _query_groq_json(
        self,
        messages: List[Dict[str, str]],
        model: str = GROQ_EXPLANATION_MODEL,
        request_timeout_seconds: float = GROQ_REQUEST_TIMEOUT_SECONDS,
        max_tokens: int = 180,
    ) -> Optional[Dict[str, Any]]:
        """Query Groq and parse a STRICT JSON object from the assistant response."""
        text = await self._query_groq_chat(
            messages=messages,
            model=model,
            temperature=0.0,
            max_tokens=max_tokens,
            request_timeout_seconds=request_timeout_seconds,
        )
        if not text:
            return None

        s = text.strip()

        if s.startswith("```"):
            s = s.replace("```json", "```").replace("```JSON", "```")
            s = s.strip("`\n ")

        try:
            parsed = json.loads(s)
            return parsed if isinstance(parsed, dict) else None
        except Exception:  # nosec B110
            pass

        start = s.find("{")
        end = s.rfind("}")
        if start >= 0 and end > start:
            try:
                parsed = json.loads(s[start : end + 1])
                return parsed if isinstance(parsed, dict) else None
            except Exception:
                return None
        return None

    async def classify_url(self, url: str) -> Dict[str, Any]:
        """
        Step 1: URL Classification using Groq

        Args:
            url: URL to classify

        Returns:
            Classification result with confidence scores
        """
        logger.debug(f"[SEARCH] Step 1: Classifying URL with Groq model: {url}")

        try:
            if not GROQ_API_KEY:
                logger.warning("Groq API key not configured; using fallback URL analysis")
                return self._fallback_url_analysis(url)

            payload = await self._query_groq_json(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity classifier. Output strict JSON only.",
                    },
                    {
                        "role": "user",
                        "content": (
                            "Classify the following URL for malicious intent (phishing/malware/scam). "
                            "Return STRICT JSON with keys: is_malicious (bool), confidence (0..1 float), label (string). "
                            "Do not include any other text.\n\n"
                            f"URL: {url}"
                        ),
                    },
                ],
                model=GROQ_EXPLANATION_MODEL,
                request_timeout_seconds=GROQ_REQUEST_TIMEOUT_SECONDS,
                max_tokens=120,
            )

            if not payload:
                logger.warning("Groq URL classification unavailable, using fallback")
                return self._fallback_url_analysis(url)

            is_malicious = bool(payload.get("is_malicious", False))
            confidence = float(payload.get("confidence", 0.0) or 0.0)
            confidence = max(0.0, min(1.0, confidence))
            label = str(payload.get("label", "unknown"))

            return {
                "success": True,
                "is_malicious": is_malicious,
                "confidence": confidence,
                "label": label,
                "model": f"groq:{GROQ_EXPLANATION_MODEL}",
                "raw_output": payload,
                "fallback": False,
            }

        except Exception as e:
            logger.error(f"URL classification error: {e}")
            return self._fallback_url_analysis(url)

    async def classify_html_content(self, html_text: str, url: str = "") -> Dict[str, Any]:
        """
        Step 2: HTML Content Classification using Groq

        Args:
            html_text: Extracted HTML text content
            url: Original URL for context

        Returns:
            Phishing classification result
        """
        logger.debug("[SEARCH] Step 2: Classifying HTML content with Groq")

        try:
            if not GROQ_API_KEY:
                logger.warning("Groq API key not configured; using fallback content analysis")
                return self._fallback_content_analysis(html_text)

            max_chars = 2500
            truncated_text = html_text[:max_chars] if len(html_text) > max_chars else html_text

            payload = await self._query_groq_json(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity classifier. Output strict JSON only.",
                    },
                    {
                        "role": "user",
                        "content": (
                            "Classify the following page content for phishing/social engineering. "
                            "Return STRICT JSON with keys: is_phishing (bool), confidence (0..1 float), label (string). "
                            "Do not include any other text.\n\n"
                            f"URL: {url}\n\n"
                            "CONTENT:\n"
                            f"{truncated_text}"
                        ),
                    },
                ],
                model=GROQ_EXPLANATION_MODEL,
                request_timeout_seconds=GROQ_REQUEST_TIMEOUT_SECONDS,
                max_tokens=160,
            )

            if not payload:
                logger.warning("Groq content classification unavailable, using fallback")
                return self._fallback_content_analysis(html_text)

            is_phishing = bool(payload.get("is_phishing", False))
            confidence = float(payload.get("confidence", 0.0) or 0.0)
            confidence = max(0.0, min(1.0, confidence))
            label = str(payload.get("label", "unknown"))

            return {
                "success": True,
                "is_phishing": is_phishing,
                "confidence": confidence,
                "label": label,
                "model": f"groq:{GROQ_EXPLANATION_MODEL}",
                "content_length": len(html_text),
                "raw_output": payload,
                "fallback": False,
            }

        except Exception as e:
            logger.error(f"Content classification error: {e}")
            return self._fallback_content_analysis(html_text)

    async def generate_explanation(
        self,
        url: str,
        url_classification: Dict[str, Any],
        content_classification: Dict[str, Any],
        ssl_analysis: Dict[str, Any],
        vt_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Step 3: Generate human-readable explanation using LLM

        Args:
            url: Scanned URL
            url_classification: Results from URL classifier
            content_classification: Results from content classifier
            ssl_analysis: SSL certificate analysis
            vt_analysis: VirusTotal analysis

        Returns:
            Comprehensive explanation with risk factors
        """
        logger.debug("[SEARCH] Step 3: Generating explanation with LLM")

        try:
            # Build context for the LLM
            context = self._build_explanation_context(
                url, url_classification, content_classification, ssl_analysis, vt_analysis
            )

            # Prefer Groq for real-time explanation generation if configured.
            # This avoids dependency on HuggingFace/Mistral API keys.
            groq_text = await self._query_groq_chat(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Provide clear, concise, user-safe explanations.",
                    },
                    {
                        "role": "user",
                        "content": (
                            "Generate a short scan explanation for a URL security report.\n\n"
                            f"URL: {url}\n"
                            f"URL classifier: label={url_classification.get('label', 'unknown')}, confidence={url_classification.get('confidence', 0):.2f}\n"
                            f"Content classifier: label={content_classification.get('label', 'unknown')}, confidence={content_classification.get('confidence', 0):.2f}\n"
                            f"SSL valid: {ssl_analysis.get('valid', False)}\n"
                            f"VirusTotal: malicious={vt_analysis.get('malicious_count', 0)}, total={vt_analysis.get('total_engines', 0)}\n\n"
                            "Return STRICT JSON with keys: explanation (string), risk_summary (string), threat_factors (array of strings), "
                            "safety_factors (array of strings), recommended_action (string). Keep explanation to 2-3 sentences."
                        ),
                    },
                ],
                model=GROQ_EXPLANATION_MODEL,
                temperature=0.2,
                max_tokens=240,
                request_timeout_seconds=GROQ_REQUEST_TIMEOUT_SECONDS,
            )

            if groq_text:
                parsed = None
                try:
                    parsed = json.loads(groq_text)
                except Exception:
                    parsed = None

                if isinstance(parsed, dict):
                    return {
                        "success": True,
                        "explanation": str(parsed.get("explanation", "")).strip() or groq_text,
                        "risk_summary": str(parsed.get("risk_summary", "")).strip()
                        or self._generate_risk_summary(context),
                        "threat_factors": (
                            parsed.get("threat_factors", context["threat_factors"])
                            if isinstance(parsed.get("threat_factors", None), list)
                            else context["threat_factors"]
                        ),
                        "safety_factors": (
                            parsed.get("safety_factors", context["safety_factors"])
                            if isinstance(parsed.get("safety_factors", None), list)
                            else context["safety_factors"]
                        ),
                        "recommended_action": str(parsed.get("recommended_action", "")).strip()
                        or context["recommended_action"],
                        "model": f"groq:{GROQ_EXPLANATION_MODEL}",
                        "fallback": False,
                    }

                # If Groq returns non-JSON, still use it as a best-effort explanation.
                return {
                    "success": True,
                    "explanation": groq_text,
                    "risk_summary": self._generate_risk_summary(context),
                    "threat_factors": context["threat_factors"],
                    "safety_factors": context["safety_factors"],
                    "recommended_action": context["recommended_action"],
                    "model": f"groq:{GROQ_EXPLANATION_MODEL}",
                    "fallback": True,
                }

            logger.warning("Groq explanation unavailable, using template-based explanation")
            return self._fallback_explanation(context)

        except Exception as e:
            logger.error(f"Explanation generation error: {e}")
            context = self._build_explanation_context(
                url, url_classification, content_classification, ssl_analysis, vt_analysis
            )
            return self._fallback_explanation(context)

    def _build_explanation_context(
        self, url: str, url_class: Dict, content_class: Dict, ssl: Dict, vt: Dict
    ) -> Dict[str, Any]:
        """Build context for explanation generation"""
        threat_factors = []
        safety_factors = []

        # Analyze URL classification
        if url_class.get("is_malicious", False):
            threat_factors.append(
                f"URL pattern indicates malicious intent ({url_class.get('confidence', 0):.0%} confidence)"
            )
        else:
            safety_factors.append("URL structure appears legitimate")

        # Analyze content classification
        if content_class.get("is_phishing", False):
            threat_factors.append(
                f"Content shows phishing indicators ({content_class.get('confidence', 0):.0%} confidence)"
            )
        else:
            safety_factors.append("Content analysis shows no phishing patterns")

        # Analyze SSL
        if not ssl.get("valid", False) and "error" not in ssl:
            threat_factors.append("Invalid or missing SSL certificate")
        elif ssl.get("valid", False):
            safety_factors.append("Valid SSL certificate detected")

        # Analyze VirusTotal
        malicious_count = vt.get("malicious_count", 0)
        if malicious_count > 0:
            threat_factors.append(f"{malicious_count} security engines flagged this URL")
        elif vt.get("total_engines", 0) > 0:
            safety_factors.append("No security engines flagged this URL")

        is_threat = len(threat_factors) > 0

        # Determine recommended action
        if malicious_count >= 3 or (url_class.get("is_malicious", False) and content_class.get("is_phishing", False)):
            recommended_action = "⛔ BLOCK - Do not visit this website. High risk of malware or phishing."
        elif is_threat:
            recommended_action = "[WARNING] CAUTION - Proceed with extreme caution. Potential security risks detected."
        else:
            recommended_action = "[OK] SAFE - Website appears legitimate. No significant threats detected."

        return {
            "url": url,
            "is_threat": is_threat,
            "threat_factors": threat_factors,
            "safety_factors": safety_factors,
            "recommended_action": recommended_action,
            "threat_level": "high" if malicious_count >= 3 else "medium" if is_threat else "low",
        }

    def _generate_risk_summary(self, context: Dict[str, Any]) -> str:
        """Generate a concise risk summary"""
        if context["is_threat"]:
            return f"This website poses security risks. {len(context['threat_factors'])} threat indicator(s) detected."
        else:
            return "This website appears safe based on our analysis."

    def _fallback_url_analysis(self, url: str) -> Dict[str, Any]:
        """Fallback rule-based URL analysis"""
        suspicious_patterns = ["login", "verify", "account", "secure", "update", "confirm"]
        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]

        is_suspicious = any(pattern in url.lower() for pattern in suspicious_patterns)
        is_suspicious = is_suspicious or any(url.endswith(tld) for tld in suspicious_tlds)

        return {
            "success": False,
            "is_malicious": is_suspicious,
            "confidence": 0.6 if is_suspicious else 0.4,
            "label": "suspicious" if is_suspicious else "benign",
            "model": "rule-based-fallback",
            "fallback": True,
        }

    def _fallback_content_analysis(self, html_text: str) -> Dict[str, Any]:
        """Fallback rule-based content analysis"""
        phishing_keywords = [
            "verify your account",
            "confirm your identity",
            "urgent action required",
            "suspended account",
            "click here immediately",
            "prize winner",
        ]

        is_phishing = any(keyword in html_text.lower() for keyword in phishing_keywords)

        return {
            "success": False,
            "is_phishing": is_phishing,
            "confidence": 0.7 if is_phishing else 0.3,
            "label": "phishing" if is_phishing else "legitimate",
            "model": "rule-based-fallback",
            "content_length": len(html_text),
            "fallback": True,
        }

    def _fallback_explanation(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback template-based explanation"""
        if context["is_threat"]:
            explanation = f"Security analysis detected {len(context['threat_factors'])} risk factor(s). "
            explanation += "This website may pose threats including phishing, malware, or fraudulent content. "
            explanation += "We recommend avoiding this site to protect your personal information and devices."
        else:
            explanation = "Our security analysis found no significant threats. "
            explanation += "The website appears to use standard security practices and shows no malicious indicators. "
            explanation += "However, always exercise caution when sharing personal information online."

        return {
            "success": False,
            "explanation": explanation,
            "risk_summary": self._generate_risk_summary(context),
            "threat_factors": context["threat_factors"],
            "safety_factors": context["safety_factors"],
            "recommended_action": context["recommended_action"],
            "model": "template-based-fallback",
            "fallback": True,
        }

    async def analyze_with_llm(
        self, url: str, html_content: str, ssl_analysis: Dict, vt_analysis: Dict
    ) -> Dict[str, Any]:
        """
        Step 4: Complete LLM-based analysis pipeline

        Combines all steps:
        1. URL Classification
        2. Content Classification
        3. Explanation Generation
        4. Final Output Fusion

        Args:
            url: URL to analyze
            html_content: HTML content extracted from the page
            ssl_analysis: SSL certificate analysis results
            vt_analysis: VirusTotal analysis results

        Returns:
            Comprehensive analysis with LLM explanations
        """
        logger.info(f"[START] Starting complete LLM analysis for: {url}")

        try:
            # Execute Steps 1 & 2 in parallel
            url_task = self.classify_url(url)
            content_task = self.classify_html_content(html_content, url)

            url_classification, content_classification = await asyncio.gather(
                url_task, content_task, return_exceptions=True
            )

            # Handle exceptions
            if isinstance(url_classification, Exception):
                logger.error(f"URL classification failed: {url_classification}")
                url_classification = self._fallback_url_analysis(url)

            if isinstance(content_classification, Exception):
                logger.error(f"Content classification failed: {content_classification}")
                content_classification = self._fallback_content_analysis(html_content)

            # Step 3: Generate explanation
            explanation = await self.generate_explanation(
                url, url_classification, content_classification, ssl_analysis, vt_analysis
            )

            # Step 4: Fuse results
            final_result = {
                "timestamp": datetime.now().isoformat(),
                "url": url,
                "llm_analysis": {
                    "url_classification": url_classification,
                    "content_classification": content_classification,
                    "explanation": explanation,
                },
                "overall_assessment": {
                    "is_malicious": url_classification.get("is_malicious", False)
                    or content_classification.get("is_phishing", False),
                    "confidence": max(
                        url_classification.get("confidence", 0), content_classification.get("confidence", 0)
                    ),
                    "threat_level": explanation.get("threat_factors", []),
                    "risk_summary": explanation.get("risk_summary", ""),
                    "recommended_action": explanation.get("recommended_action", ""),
                },
                "models_used": {
                    "url_classifier": url_classification.get("model", "unknown"),
                    "content_classifier": content_classification.get("model", "unknown"),
                    "explanation_generator": explanation.get("model", "unknown"),
                },
            }

            logger.info(f"[OK] Complete LLM analysis finished for: {url}")
            return final_result

        except Exception as e:
            logger.error(f"Complete LLM analysis error: {e}")
            return {
                "timestamp": datetime.now().isoformat(),
                "url": url,
                "error": str(e),
                "llm_analysis": None,
                "overall_assessment": {
                    "is_malicious": False,
                    "confidence": 0.0,
                    "threat_level": [],
                    "risk_summary": "Analysis failed",
                    "recommended_action": "Unable to assess - please try again",
                },
            }


# Singleton instance
_llm_service_instance = None


async def get_llm_service() -> LLMService:
    """Get or create LLM service instance"""
    global _llm_service_instance
    if _llm_service_instance is None:
        _llm_service_instance = LLMService()
    return _llm_service_instance
