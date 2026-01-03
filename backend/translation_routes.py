import logging
import time
from typing import Dict, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .translation_service import translation_service

logger = logging.getLogger(__name__)

translation_router = APIRouter(prefix="/api/translations", tags=["translations"])


class TranslateRequest(BaseModel):
    text: str
    target_lang: str
    context: str | None = "cybersecurity"


class TranslateBatchRequest(BaseModel):
    texts: List[str]
    target_lang: str
    context: str | None = "cybersecurity"


@translation_router.get("/languages")
async def get_supported_languages():
    """Get list of supported languages"""
    return {"languages": translation_service.supported_languages, "default": "en"}


@translation_router.get("/ui/{lang_code}")
async def get_ui_translations(lang_code: str):
    """Get all UI translations for a specific language"""
    if lang_code not in translation_service.supported_languages:
        raise HTTPException(status_code=400, detail="Unsupported language")

    try:
        translations = await translation_service.get_ui_translations(lang_code)
        return {"language": lang_code, "translations": translations}
    except Exception as e:
        logger.error(f"Failed to get UI translations for {lang_code}: {e}")
        raise HTTPException(status_code=500, detail="Translation service error")


@translation_router.post("/translate")
async def translate_text(request: TranslateRequest):
    """Translate a single text string"""
    if request.target_lang not in translation_service.supported_languages:
        raise HTTPException(status_code=400, detail="Unsupported language")

    try:
        translated = await translation_service.translate_text(
            request.text, request.target_lang, request.context or "cybersecurity"
        )
        return {"original": request.text, "translated": translated, "target_language": request.target_lang}
    except Exception as e:
        logger.error(f"Translation failed: {e}")
        raise HTTPException(status_code=500, detail="Translation failed")


@translation_router.post("/translate/batch")
async def translate_batch(request: TranslateBatchRequest):
    """Translate multiple text strings with enhanced error handling and performance metrics"""
    if request.target_lang not in translation_service.supported_languages:
        raise HTTPException(status_code=400, detail="Unsupported language")

    # Validate input
    if not request.texts:
        return {
            "translations": {},
            "target_language": request.target_lang,
            "count": 0,
            "cached_count": 0,
            "processing_time_ms": 0,
        }

    # Limit batch size for performance
    if len(request.texts) > 100:
        raise HTTPException(status_code=400, detail="Batch size too large. Maximum 100 texts per request.")

    start_time = time.time()

    try:
        translations = await translation_service.translate_batch(
            request.texts, request.target_lang, request.context or "cybersecurity"
        )

        processing_time = int((time.time() - start_time) * 1000)
        cached_count = sum(1 for text in request.texts if text in translations and translations[text] == text)

        return {
            "translations": translations,
            "target_language": request.target_lang,
            "count": len(translations),
            "cached_count": cached_count,
            "processing_time_ms": processing_time,
            "success": True,
        }
    except Exception as e:
        logger.error(f"Batch translation failed: {e}")
        processing_time = int((time.time() - start_time) * 1000)

        # Return partial results if available
        return {
            "translations": {text: text for text in request.texts},  # Fallback to originals
            "target_language": request.target_lang,
            "count": len(request.texts),
            "cached_count": 0,
            "processing_time_ms": processing_time,
            "success": False,
            "error": "Translation service temporarily unavailable",
        }


@translation_router.get("/scan-result/{lang_code}")
async def get_scan_result_translations(lang_code: str):
    """Get translations for scan result messages"""
    if lang_code not in translation_service.supported_languages:
        raise HTTPException(status_code=400, detail="Unsupported language")

    scan_messages = {
        "threat.high": "High Risk - This URL poses significant security threats",
        "threat.medium": "Medium Risk - Exercise caution when visiting this URL",
        "threat.low": "Low Risk - This URL appears to be safe",
        "threat.safe": "Safe - No security threats detected",
        "ssl.valid": "SSL certificate is valid and secure",
        "ssl.invalid": "SSL certificate is invalid or expired",
        "ssl.missing": "No SSL certificate found - connection is not secure",
        "vt.malicious": "Detected as malicious by security engines",
        "vt.suspicious": "Flagged as suspicious by security engines",
        "vt.clean": "No threats detected by security engines",
        "analysis.complete": "Security analysis completed successfully",
        "analysis.failed": "Security analysis could not be completed",
        "domain.trusted": "Domain is in trusted whitelist",
        "domain.unknown": "Domain reputation is unknown",
    }

    try:
        if lang_code == "en":
            return {"language": lang_code, "messages": scan_messages}

        translations = await translation_service.translate_batch(
            list(scan_messages.values()), lang_code, "security analysis"
        )

        translated_messages = {}
        for key, original_text in scan_messages.items():
            translated_messages[key] = translations.get(original_text, original_text)

        return {"language": lang_code, "messages": translated_messages}
    except Exception as e:
        logger.error(f"Failed to get scan result translations: {e}")
        raise HTTPException(status_code=500, detail="Translation service error")
