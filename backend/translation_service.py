import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


class GeminiTranslationService:
    def __init__(self):
        self.cache_dir = Path("translations")
        self.cache_dir.mkdir(exist_ok=True)

        # Supported languages for WebShield
        self.supported_languages = {
            "en": "English",
            "es": "Spanish",
            "fr": "French",
            "de": "German",
            "pt": "Portuguese",
            "it": "Italian",
            "ja": "Japanese",
            "ko": "Korean",
        }

    async def translate_text(self, text: str, target_lang: str, context: str = "cybersecurity") -> str:
        """Translate text using offline cached fallback translations"""
        if target_lang == "en":
            return text

        # Check cache first
        cached = self._get_cached_translation(text, target_lang)
        if cached:
            return cached

        translated = self._get_fallback_translation(text, target_lang)
        if translated and translated != text:
            self._cache_translation(text, target_lang, translated)
        return translated

    async def translate_batch(
        self, texts: List[str], target_lang: str, context: str = "cybersecurity"
    ) -> Dict[str, str]:
        """Translate multiple texts with enhanced caching, batching, and resilient fallback.

        Uses intelligent batching to reduce API calls while maintaining reliability.
        Implements progressive fallback for maximum uptime.
        """
        results: Dict[str, str] = {}

        if not texts:
            return results

        # Fast-path for English
        if target_lang == "en":
            return {t: t for t in texts}

        # First, fill from cache
        uncached_texts: List[str] = []
        for text in texts:
            cached = self._get_cached_translation(text, target_lang)
            if cached is not None:
                results[text] = cached
            else:
                uncached_texts.append(text)

        for text in uncached_texts:
            results[text] = self._get_fallback_translation(text, target_lang)
        return results

    def _build_translation_prompt(self, text: str, target_lang: str, context: str) -> str:
        """Build context-aware translation prompt"""
        lang_name = self.supported_languages.get(target_lang, target_lang)

        return f"""Translate the following {context} text to {lang_name}.

Important guidelines:
- Maintain technical accuracy for cybersecurity terms
- Keep security warnings appropriately serious in tone
- Preserve any technical terminology that should remain in English
- For UI elements, use standard conventions for the target language
- Do not translate brand names like "WebShield"

Text to translate:
{text}

Translation:"""

    def _get_cached_translation(self, text: str, target_lang: str) -> Optional[str]:
        """Get translation from cache"""
        cache_file = self.cache_dir / f"{target_lang}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cache = json.load(f)
                    return cache.get(text)  # type: ignore[return-value]
            except Exception:
                return None
        return None

    def _cache_translation(self, original: str, target_lang: str, translation: str):
        """Cache translation for future use"""
        cache_file = self.cache_dir / f"{target_lang}.json"
        cache = {}

        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cache = json.load(f)
            except Exception:
                cache = {}

        cache[original] = translation

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to cache translation: {e}")

    def _get_fallback_translation(self, text: str, target_lang: str) -> str:
        """Provide basic fallback translations for common UI elements"""
        # Basic fallback translations for common terms
        fallback_translations = {
            "es": {  # Spanish
                "Home": "Inicio",
                "Features": "Características",
                "Dashboard": "Panel",
                "About": "Acerca de",
                "Login": "Iniciar sesión",
                "Register": "Registrarse",
                "Scan URL": "Escanear URL",
                "Translate": "Traducir",
                "Loading...": "Cargando...",
                "Safe": "Seguro",
                "Warning": "Advertencia",
                "Dangerous": "Peligroso",
                "Advanced Web Security": "Seguridad Web Avanzada",
                "Protection You Can Trust": "Protección en la que Puedes Confiar",
            },
            "fr": {  # French
                "Home": "Accueil",
                "Features": "Fonctionnalités",
                "Dashboard": "Tableau de bord",
                "About": "À propos",
                "Login": "Connexion",
                "Register": "S'inscrire",
                "Scan URL": "Scanner URL",
                "Translate": "Traduire",
                "Loading...": "Chargement...",
                "Safe": "Sûr",
                "Warning": "Avertissement",
                "Dangerous": "Dangereux",
                "Advanced Web Security": "Sécurité Web Avancée",
                "Protection You Can Trust": "Protection de Confiance",
            },
            "de": {  # German
                "Home": "Startseite",
                "Features": "Funktionen",
                "Dashboard": "Dashboard",
                "About": "Über uns",
                "Login": "Anmelden",
                "Register": "Registrieren",
                "Scan URL": "URL scannen",
                "Translate": "Übersetzen",
                "Loading...": "Laden...",
                "Safe": "Sicher",
                "Warning": "Warnung",
                "Dangerous": "Gefährlich",
                "Advanced Web Security": "Erweiterte Web-Sicherheit",
                "Protection You Can Trust": "Vertrauensvoller Schutz",
            },
            "pt": {  # Portuguese
                "Home": "Início",
                "Features": "Recursos",
                "Dashboard": "Painel",
                "About": "Sobre",
                "Login": "Entrar",
                "Register": "Registrar",
                "Scan URL": "Escanear URL",
                "Translate": "Traduzir",
                "Loading...": "Carregando...",
                "Safe": "Seguro",
                "Warning": "Aviso",
                "Dangerous": "Perigoso",
                "Advanced Web Security": "Segurança Web Avançada",
                "Protection You Can Trust": "Proteção Confiável",
            },
            "it": {  # Italian
                "Home": "Home",
                "Features": "Funzionalità",
                "Dashboard": "Dashboard",
                "About": "Chi siamo",
                "Login": "Accedi",
                "Register": "Registrati",
                "Scan URL": "Scansiona URL",
                "Translate": "Traduci",
                "Loading...": "Caricamento...",
                "Safe": "Sicuro",
                "Warning": "Avvertimento",
                "Dangerous": "Pericoloso",
                "Advanced Web Security": "Sicurezza Web Avanzata",
                "Protection You Can Trust": "Protezione Affidabile",
            },
            "ja": {  # Japanese
                "Home": "ホーム",
                "Features": "機能",
                "Dashboard": "ダッシュボード",
                "About": "概要",
                "Login": "ログイン",
                "Register": "登録",
                "Scan URL": "URLスキャン",
                "Translate": "翻訳",
                "Loading...": "読み込み中...",
                "Safe": "安全",
                "Warning": "警告",
                "Dangerous": "危険",
                "Advanced Web Security": "高度なWebセキュリティ",
                "Protection You Can Trust": "信頼できる保護",
            },
            "ko": {  # Korean
                "Home": "홈",
                "Features": "기능",
                "Dashboard": "대시보드",
                "About": "소개",
                "Login": "로그인",
                "Register": "회원가입",
                "Scan URL": "URL 스캔",
                "Translate": "번역",
                "Loading...": "로딩 중...",
                "Safe": "안전",
                "Warning": "경고",
                "Dangerous": "위험",
                "Advanced Web Security": "고급 웹 보안",
                "Protection You Can Trust": "신뢰할 수 있는 보호",
            },
        }

        if target_lang in fallback_translations:
            return fallback_translations[target_lang].get(text, text)

        return text

    async def get_ui_translations(self, target_lang: str) -> Dict[str, str]:
        """Get all UI translations for a language"""
        ui_strings = {
            # Navigation
            "nav.home": "Home",
            "nav.features": "Features",
            "nav.dashboard": "Dashboard",
            "nav.about": "About",
            "nav.login": "Login",
            "nav.register": "Register",
            # Scanning
            "scan.title": "URL Security Scan",
            "scan.placeholder": "Enter URL to scan...",
            "scan.button": "Scan URL",
            "scan.analyzing": "Analyzing...",
            "scan.complete": "Scan Complete",
            # Results
            "result.safe": "Safe",
            "result.warning": "Warning",
            "result.danger": "Dangerous",
            "result.threat_level": "Threat Level",
            "result.ssl_valid": "SSL Certificate Valid",
            "result.malicious_count": "Malicious Detections",
            # Errors
            "error.invalid_url": "Invalid URL format",
            "error.scan_failed": "Scan failed. Please try again.",
            "error.network": "Network error occurred",
            # Common
            "common.loading": "Loading...",
            "common.retry": "Retry",
            "common.back": "Back",
            "common.close": "Close",
        }

        if target_lang == "en":
            return ui_strings

        # Translate all UI strings
        translations = await self.translate_batch(list(ui_strings.values()), target_lang, "user interface")

        # Map back to keys
        result = {}
        for key, original_text in ui_strings.items():
            result[key] = translations.get(original_text, original_text)

        return result


# Global translation service instance
translation_service = GeminiTranslationService()
