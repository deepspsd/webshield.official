import pytest
from fastapi.testclient import TestClient

from backend.server import app

client = TestClient(app, base_url="http://testserver")
client.headers.update({"Host": "testserver"})


class TestTranslationRoutes:
    def test_languages_endpoint(self):
        resp = client.get("/api/translations/languages")
        assert resp.status_code == 200
        data = resp.json()
        assert "languages" in data
        assert "default" in data
        assert data["default"] == "en"
        assert isinstance(data["languages"], dict)
        assert "en" in data["languages"]

    def test_ui_translations_en(self):
        resp = client.get("/api/translations/ui/en")
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "en"
        assert "translations" in data
        assert isinstance(data["translations"], dict)
        # Known key
        assert "nav.home" in data["translations"]

    def test_translate_batch_empty(self):
        resp = client.post(
            "/api/translations/translate/batch",
            json={"texts": [], "target_lang": "es", "context": "web"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["translations"] == {}
        assert data["count"] == 0
        assert data["target_language"] == "es"

    def test_translate_batch_unsupported_language(self):
        resp = client.post(
            "/api/translations/translate/batch",
            json={"texts": ["Home"], "target_lang": "xx"},
        )
        assert resp.status_code == 400

    def test_translate_batch_fallback_without_api_key(self, monkeypatch):
        # Force service to behave as if Gemini is not configured
        from backend.translation_service import translation_service

        monkeypatch.setattr(translation_service, "model", None, raising=False)

        texts = ["Home", "Scan URL", "Translate"]
        resp = client.post(
            "/api/translations/translate/batch",
            json={"texts": texts, "target_lang": "es", "context": "web"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "translations" in data
        translations = data["translations"]
        assert isinstance(translations, dict)
        # Should return entries for all requested texts
        for t in texts:
            assert t in translations
        # At least one known fallback should translate
        assert translations["Home"] in ("Inicio", "Home")
