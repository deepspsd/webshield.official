"""
WebShield Chatbot Assistant
AI-powered help system for users to understand security features and scan results
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import requests

try:
    from sklearn.feature_extraction.text import HashingVectorizer
except Exception:  # pragma: no cover
    HashingVectorizer = None

try:
    import chromadb
except Exception:  # pragma: no cover
    chromadb = None

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover
    PdfReader = None


class WebShieldChatbot:
    """AI-powered chatbot assistant for WebShield"""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize chatbot with Groq + local RAG (Chroma)"""
        self.groq_api_key = api_key or os.getenv("GROQ_API_KEY")
        self.groq_api_base = os.getenv("GROQ_API_BASE", "https://api.groq.com/openai/v1")
        # Highest-throughput free-tier default (can override via env)
        self.groq_model = os.getenv("GROQ_CHATBOT_MODEL", "llama-3.1-8b-instant")
        self.groq_timeout_seconds = float(os.getenv("GROQ_REQUEST_TIMEOUT_SECONDS", "6"))

        self.use_ai = bool(self.groq_api_key)
        if not self.use_ai:
            print("Warning: No Groq API key found. Using fallback responses.")

        self.project_root = Path(__file__).resolve().parents[1]
        self.legal_docs_dir = Path(os.getenv("CHATBOT_KB_DIR", str(self.project_root / "legal_docs"))).resolve()
        self.chroma_dir = Path(os.getenv("CHATBOT_CHROMA_DIR", str(self.project_root / ".chroma_webshield"))).resolve()
        self.collection_name = os.getenv("CHATBOT_CHROMA_COLLECTION", "webshield_legal_docs")
        self.embedding_dim = int(os.getenv("CHATBOT_EMBED_DIM", "1024"))

        self._vectorizer = None
        self._chroma_client = None
        self._chroma_collection = None
        self._kb_ready = False
        self._kb_error = None

        # System context for the AI
        self.system_context = """
You are WebShield AI Assistant, a professional security expert helping users understand web security and threat protection.

Your role:
- Explain WebShield's advanced security features professionally
- Educate users about cyber threats (phishing, malware, SSL vulnerabilities, typosquatting)
- Interpret scan results and threat scores clearly
- Provide actionable security recommendations
- Answer technical questions in an accessible way

WebShield Platform Overview:
- Enterprise-grade web security with 95%+ threat detection accuracy
- Multi-engine detection system: VirusTotal (90+ scanners), ML models, SSL validation, pattern analysis
- Ensemble AI: 4 ML models (Random Forest + Gradient Boosting + SVM + Neural Network)
- Trained on 650,000+ URLs with 50+ URL features and 30+ content features
- Real-time scanning with sub-2-second response times
- Detects: phishing, malware, typosquatting, brand impersonation, SSL issues, suspicious patterns
- Browser extension for automatic real-time protection
- Comprehensive threat intelligence and detailed analysis reports

Response Guidelines:
- Be professional, clear, and authoritative
- Use 2-4 sentences for concise answers
- Explain technical concepts in simple terms
- Provide specific, actionable advice
- Reference WebShield's capabilities accurately
- Use security terminology appropriately
- Be helpful and reassuring while maintaining professionalism

When users report issues or need support:
- Acknowledge their concern empathetically
- Direct them to support@webshield.com for technical issues, bugs, or problems
- Suggest including relevant details (error messages, screenshots, steps to reproduce)
- For security vulnerabilities, mention marking subject as 'SECURITY' for priority
- For urgent matters, suggest including 'URGENT' in subject line
- Offer to help with general questions while routing technical issues to support team

When explaining scan results:
- Interpret threat scores (0-30: safe, 31-70: suspicious, 71-100: dangerous)
- Explain what specific detections mean
- Provide clear recommendations (visit/avoid/report)
- Mention which detection engines flagged the URL
"""

        self.rag_system_rules = (
            "You answer questions using ONLY the provided Knowledge Base excerpts when they are available. "
            "If the answer is not present in the excerpts, say you don't have enough information in the knowledge base and "
            "suggest contacting support@webshield.com. "
            "Be professional, concise (2-6 sentences), and actionable. "
            "When you use knowledge base information, include a short 'Sources:' section listing the filenames you relied on."
        )

        # Fallback responses for common questions
        self.fallback_responses = {
            "hi": "Hello! I'm WebShield AI Assistant. How can I help you today—do you want to understand a scan result, learn about threats (phishing/malware), or review our policies and security terms?",
            "hello": "Hello! I'm WebShield AI Assistant. What can I help you with today—scan results, web security questions, or WebShield policies?",
            "hey": "Hi! How can I help you with WebShield today?",
            "different types of cyber threats": "WebShield can help you understand different types of cyber threats, including phishing, malware, typosquatting, brand impersonation, SSL issues, and suspicious patterns. How can I help you today?",
            "how to check URL's": "To check a URL, paste it into the scanner ongate to  our homepage and click 'Scan URL'. WebShield will analyze it using multiple detection engines and return a risk level (safe/suspicious/dangerous) with a detailed report.You can also use our browser extension for instant protection while browsing.",
            "how to check url": "To check a URL, paste it into the scanner on our homepage and click 'Scan URL'. WebShield will analyze it using multiple detection engines and return a risk level (safe/suspicious/dangerous) with a detailed report.You can also use our browser extension for instant protection while browsing.",
            "issue": "I understand you're experiencing an issue. Our support team is here to help! Please contact us at **support@webshield.com** with details about the problem, and we'll assist you promptly. For urgent matters, please include 'URGENT' in your subject line.",
            "problem": "I'm sorry to hear you're having a problem. For personalized assistance, please reach out to our technical support team at **support@webshield.com**. Include any error messages or screenshots to help us resolve this quickly.",
            "bug": "Thank you for reporting this bug! Please send detailed information to our development team at **support@webshield.com**. Include steps to reproduce the issue, your browser/system details, and any error messages. We appreciate your help in improving WebShield!",
            "error": "I see you're encountering an error. For technical support, please contact our team at **support@webshield.com** with the error details. Our engineers will investigate and provide a solution as soon as possible.",
            "not working": "I apologize for the inconvenience. If something isn't working as expected, please email our support team at **support@webshield.com** with specific details about what's not functioning. We're committed to resolving this for you quickly.",
            "help": "I'm here to help! For general questions, I can assist you right now. For technical issues, account problems, or specific support needs, please contact our dedicated support team at **support@webshield.com**. How can I help you today?",
            "support": "For comprehensive support, our team is available at **support@webshield.com**. We typically respond within 24 hours. For immediate assistance with common questions, feel free to ask me here!",
            "contact": "You can reach our support team at **support@webshield.com** for any questions, issues, or feedback. We're here to help! Is there something specific I can assist you with right now?",
            "report": "Thank you for wanting to report this! Please send your report to **support@webshield.com** with as much detail as possible. If you're reporting a security vulnerability, please mark it as 'SECURITY' in the subject line for priority handling.",
            "how does it work": "WebShield employs a multi-layered security approach: our ensemble AI models analyze 50+ URL features, VirusTotal checks against 90+ antivirus engines, SSL validators verify certificates, and pattern recognition detects suspicious structures. All scans complete in under 2 seconds with 95%+ accuracy, providing comprehensive threat intelligence in real-time.",
            "how does webshield": "WebShield employs a multi-layered security approach: our ensemble AI models analyze 50+ URL features, VirusTotal checks against 90+ antivirus engines, SSL validators verify certificates, and pattern recognition detects suspicious structures. All scans complete in under 2 seconds with 95%+ accuracy.",
            "what is phishing": "Phishing is a cyber attack where criminals create fraudulent websites impersonating legitimate services (banks, PayPal, Microsoft) to steal credentials and sensitive data. WebShield detects phishing through advanced ML models trained on 650,000+ URLs, analyzing content patterns, brand impersonation indicators, and suspicious URL structures with high precision.",
            "check url": "To scan a URL, simply paste it into the scanner on our homepage and click 'Scan URL'. WebShield will analyze it through multiple detection engines and provide a comprehensive threat report within 2 seconds, including a color-coded risk assessment: Green (safe), Yellow (suspicious), or Red (dangerous).",
            "url safe": "To verify URL safety, use our scanner on the homepage. WebShield performs multi-engine analysis including AI threat detection, VirusTotal scanning, SSL validation, and pattern recognition. You'll receive a detailed report with threat score, risk level, and specific security findings.",
            "what is malware": "Malware (malicious software) includes viruses, trojans, ransomware, and spyware designed to compromise systems, steal data, or cause damage. WebShield detects malware distribution sites by cross-referencing URLs against 90+ antivirus engines via VirusTotal, combined with behavioral analysis and threat intelligence feeds.",
            "how accurate": "WebShield achieves 95%+ threat detection accuracy through our ensemble ML approach: 4 specialized models (Random Forest, Gradient Boosting, SVM, Neural Network) trained on 650,000+ URLs. This multi-model voting system, combined with VirusTotal integration and heuristic analysis, ensures highly reliable threat identification with minimal false positives.",
            "what is ssl": "SSL/TLS (Secure Sockets Layer/Transport Layer Security) provides encrypted communication between browsers and servers, protecting data in transit. WebShield validates SSL certificates by checking authenticity, expiration dates, issuer reputation, and encryption strength. Invalid or self-signed certificates are flagged as potential security risks.",
            "browser extension": "Our Chrome extension provides real-time protection by automatically scanning URLs as you browse. It features smart caching (1-hour TTL), offline mode support, and seamless integration with WebShield's backend. Install from the Chrome Web Store for continuous, automatic threat detection without impacting browsing performance.",
            "scan history": "Your scan history provides a comprehensive audit trail of all analyzed URLs, including timestamps, threat scores, risk levels, and detection details. Access it from your dashboard after logging in. This feature helps track suspicious patterns and maintain security awareness over time.",
            "threat score": "Threat scores range from 0-100 and aggregate findings from all detection engines: 0-30 indicates safe (low risk), 31-70 suggests suspicious activity (proceed with caution), 71-100 signals dangerous (avoid immediately). The score weighs ML predictions, VirusTotal detections, SSL issues, and pattern analysis for comprehensive risk assessment.",
            "features": "WebShield offers enterprise-grade features: real-time URL scanning with 95%+ accuracy, ensemble AI models, VirusTotal integration (90+ engines), SSL certificate validation, typosquatting detection, brand impersonation analysis, browser extension, scan history tracking, detailed threat reports, and API access for custom integrations.",
            "typosquatting": "Typosquatting is when attackers register domains similar to legitimate sites (e.g., 'paypa1.com' instead of 'paypal.com') to deceive users. WebShield detects typosquatting using Levenshtein distance algorithms, homograph attack detection, and brand similarity scoring across 20+ major brands.",
            "virustotal": "VirusTotal is a threat intelligence platform that aggregates 90+ antivirus engines and URL scanners. WebShield integrates with VirusTotal to cross-reference URLs against this extensive database, providing comprehensive malware and phishing detection from multiple security vendors simultaneously.",
            "machine learning": "WebShield uses ensemble machine learning with 4 specialized models: Random Forest for pattern recognition, Gradient Boosting for sequential learning, SVM for classification boundaries, and Neural Networks for complex patterns. Trained on 650,000+ URLs with 50+ features, this approach achieves 95%+ accuracy through model voting consensus.",
            "default": "I'm WebShield AI Assistant, here to help you understand web security and our platform's capabilities. I can explain:\n\n• How our multi-engine detection system works\n• Threat types (phishing, malware, SSL issues)\n• How to interpret scan results and threat scores\n• Security best practices and recommendations\n• WebShield features and integrations\n\nWhat would you like to know about web security?",
        }

        self._ensure_kb_ready()

    def _is_greeting(self, text: str) -> bool:
        s = (text or "").strip().lower()
        if not s:
            return True
        if s in {"hi", "hello", "hey", "hola", "namaste", "hii", "hiii"}:
            return True
        if re.fullmatch(r"(hi+|hey+|hello+)[!. ]*", s):
            return True
        return False

    def _ensure_kb_ready(self) -> None:
        """Initialize Chroma + embeddings and index legal_docs PDFs if needed."""
        if self._kb_ready:
            return

        if chromadb is None or HashingVectorizer is None or PdfReader is None:
            self._kb_error = (
                "RAG dependencies are not available. Ensure 'chromadb', 'scikit-learn', and 'pypdf' are installed."
            )
            return

        try:
            self.chroma_dir.mkdir(parents=True, exist_ok=True)
            self._chroma_client = chromadb.PersistentClient(path=str(self.chroma_dir))
            self._chroma_collection = self._chroma_client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            self._vectorizer = HashingVectorizer(
                n_features=self.embedding_dim,
                alternate_sign=False,
                norm=None,
                lowercase=True,
                ngram_range=(1, 2),
            )

            force_reindex = os.getenv("CHATBOT_RAG_FORCE_REINDEX", "0").strip() in {"1", "true", "True"}

            # Determine if we need to build/update the index.
            kb_fingerprint = self._compute_kb_fingerprint()
            stored_fp = None
            try:
                meta = self._chroma_collection.get(include=["metadatas"], limit=1)
                if meta and meta.get("metadatas"):
                    md0 = meta["metadatas"][0]
                    if isinstance(md0, dict):
                        stored_fp = md0.get("kb_fingerprint")
            except Exception:
                stored_fp = None

            if force_reindex or (stored_fp != kb_fingerprint):
                try:
                    # Best-effort clear.
                    self._chroma_collection.delete(where={})
                except Exception:
                    pass
                try:
                    self._index_legal_pdfs(kb_fingerprint=kb_fingerprint)
                except Exception as e:
                    # Keep the service alive even if KB indexing fails.
                    self._kb_error = f"Knowledge base indexing failed: {e}"

            self._kb_ready = True
        except Exception as e:
            self._kb_error = f"Failed to initialize knowledge base: {e}"

    def _compute_kb_fingerprint(self) -> str:
        """Fingerprint of the KB based on PDF paths + mtimes + sizes."""
        h = hashlib.sha256()
        if not self.legal_docs_dir.exists():
            h.update(b"missing")
            return h.hexdigest()

        pdfs = sorted([p for p in self.legal_docs_dir.rglob("*") if p.is_file() and p.suffix.lower() == ".pdf"])
        for p in pdfs:
            try:
                st = p.stat()
                h.update(str(p.relative_to(self.project_root)).encode("utf-8", errors="ignore"))
                h.update(str(int(st.st_mtime)).encode("utf-8"))
                h.update(str(st.st_size).encode("utf-8"))
            except Exception:
                continue
        return h.hexdigest()

    def _read_pdf_text(self, pdf_path: Path) -> List[Tuple[int, str]]:
        reader = PdfReader(str(pdf_path))
        pages: List[Tuple[int, str]] = []
        for i, page in enumerate(reader.pages):
            try:
                text = page.extract_text() or ""
            except Exception:
                text = ""
            cleaned = re.sub(r"\s+", " ", text).strip()
            if cleaned:
                pages.append((i + 1, cleaned))
        return pages

    def _chunk_text(self, text: str, chunk_size: int = 1200, overlap: int = 200) -> List[str]:
        """Simple character-based chunker with overlap."""
        s = re.sub(r"\s+", " ", text).strip()
        if not s:
            return []

        chunks: List[str] = []
        start = 0
        n = len(s)
        while start < n:
            end = min(n, start + chunk_size)
            chunk = s[start:end].strip()
            if chunk:
                chunks.append(chunk)
            if end >= n:
                break
            start = max(0, end - overlap)
        return chunks

    def _index_legal_pdfs(self, kb_fingerprint: str) -> None:
        if not self.legal_docs_dir.exists():
            raise RuntimeError(f"Knowledge base directory not found: {self.legal_docs_dir}")
        assert self._chroma_collection is not None
        assert self._vectorizer is not None

        pdf_paths = sorted([p for p in self.legal_docs_dir.rglob("*") if p.is_file() and p.suffix.lower() == ".pdf"])
        if not pdf_paths:
            # Nothing to index.
            return

        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict] = []
        embeddings: List[List[float]] = []

        for pdf_path in pdf_paths:
            pages = self._read_pdf_text(pdf_path)
            for page_num, page_text in pages:
                for chunk_idx, chunk in enumerate(self._chunk_text(page_text)):
                    rel = str(pdf_path.relative_to(self.project_root))
                    doc_id = f"{rel}::p{page_num}::c{chunk_idx}"
                    ids.append(doc_id)
                    docs.append(chunk)
                    metas.append(
                        {
                            "source": rel,
                            "page": page_num,
                            "chunk": chunk_idx,
                            "kb_fingerprint": kb_fingerprint,
                        }
                    )

        batch_size = int(os.getenv("CHATBOT_EMBED_BATCH", "128"))
        for i in range(0, len(docs), batch_size):
            batch_docs = docs[i : i + batch_size]
            embeddings.extend(self._embed_texts(batch_docs))

        self._chroma_collection.add(ids=ids, documents=docs, metadatas=metas, embeddings=embeddings)

    def _friendly_source_name(self, source_path: str) -> str:
        name = os.path.basename(source_path or "").lower()
        if name == "privacy_policy_qa.pdf":
            return "privacy policy docs"
        if name == "security_policy_qa.pdf":
            return "Security docs"
        if name == "terms_of_service_qa.pdf":
            return "Terms of service docs"
        # Fallback to filename without extension
        base = os.path.splitext(os.path.basename(source_path or "unknown"))[0]
        return base.replace("_", " ").strip() or "unknown docs"

    def _embed_texts(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        assert self._vectorizer is not None

        X = self._vectorizer.transform(texts)
        arr = X.toarray().astype(np.float32, copy=False)
        norms = np.linalg.norm(arr, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)
        arr = arr / norms
        return arr.tolist()

    def _retrieve(self, query: str, k: int = 5) -> List[Dict[str, str]]:
        """Return retrieved chunks with minimal metadata for prompt building."""
        if not self._kb_ready or not self._chroma_collection or not self._vectorizer:
            return []

        q_emb = self._embed_texts([query])[0]
        res = self._chroma_collection.query(
            query_embeddings=[q_emb],
            n_results=max(1, k),
            include=["documents", "metadatas", "distances"],
        )
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]

        retrieved: List[Dict[str, str]] = []
        for doc, md in zip(docs, metas, strict=False):
            if not isinstance(doc, str) or not doc.strip():
                continue
            source = "unknown"
            if isinstance(md, dict):
                source = str(md.get("source", "unknown"))
            label = self._friendly_source_name(source)
            retrieved.append({"source": label, "text": doc.strip()})
        return retrieved

    def _query_groq(
        self, messages: List[Dict[str, str]], temperature: float = 0.2, max_tokens: int = 512
    ) -> Optional[str]:
        if not self.groq_api_key:
            return None

        url = f"{self.groq_api_base.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self.groq_api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.groq_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        try:
            r = requests.post(url, headers=headers, json=payload, timeout=self.groq_timeout_seconds)
            if r.status_code != 200:
                return None
            data = r.json()
            choices = data.get("choices") if isinstance(data, dict) else None
            if not isinstance(choices, list) or not choices:
                return None
            msg = choices[0].get("message") if isinstance(choices[0], dict) else None
            content = msg.get("content") if isinstance(msg, dict) else None
            return content.strip() if isinstance(content, str) and content.strip() else None
        except Exception:
            return None

    def get_kb_status(self) -> Dict[str, object]:
        pdf_count = 0
        try:
            if self.legal_docs_dir.exists():
                pdf_count = len(
                    [p for p in self.legal_docs_dir.rglob("*") if p.is_file() and p.suffix.lower() == ".pdf"]
                )
        except Exception:
            pdf_count = 0

        doc_count = None
        try:
            if self._chroma_collection is not None:
                doc_count = self._chroma_collection.count()
        except Exception:
            doc_count = None

        return {
            "ai_enabled": bool(self.use_ai),
            "groq_model": self.groq_model,
            "kb_ready": bool(self._kb_ready),
            "kb_error": self._kb_error,
            "kb_dir": str(self.legal_docs_dir),
            "kb_pdf_count": pdf_count,
            "chroma_dir": str(self.chroma_dir),
            "chroma_collection": self.collection_name,
            "chroma_doc_count": doc_count,
        }

    def get_response(self, user_message: str, context: Optional[Dict] = None) -> str:
        """
        Generate chatbot response

        Args:
            user_message: User's question or message
            context: Optional context (scan results, user info, etc.)

        Returns:
            Chatbot response string
        """
        if self.use_ai:
            return self._get_ai_response(user_message, context)

        # Fallback only when AI is completely unavailable
        return self._get_fallback_response(user_message)

    def _get_ai_response(self, user_message: str, context: Optional[Dict] = None) -> str:
        """Get AI-powered response using Groq + RAG over legal_docs PDFs"""
        try:
            self._ensure_kb_ready()

            # Try to retrieve relevant documents from knowledge base
            retrieved = self._retrieve(user_message, k=int(os.getenv("CHATBOT_RETRIEVAL_K", "5")))

            # Check if this is a simple greeting
            is_greeting = self._is_greeting(user_message)

            # For greetings without RAG context, use friendly fallback
            if is_greeting and not retrieved and not context:
                return self._get_fallback_response("hello")

            kb_block = ""
            if retrieved:
                for i, item in enumerate(retrieved, start=1):
                    src = item.get("source", "unknown")
                    txt = item.get("text", "")
                    kb_block += f"\n\n[KB-{i}] Source: {src}\n{txt}"

            user_context = ""
            if context:
                user_context = json.dumps(context, indent=2)

            system_msg = f"{self.system_context}\n\n{self.rag_system_rules}"

            user_msg = (
                "Answer the user question.\n\n"
                + (f"User Context (JSON):\n{user_context}\n\n" if user_context else "")
                + (
                    f"Knowledge Base Excerpts:{kb_block}\n\n"
                    if kb_block
                    else "Knowledge Base Excerpts: (none found)\n\n"
                )
                + f"User Question: {user_message}"
            )

            text = self._query_groq(
                messages=[{"role": "system", "content": system_msg}, {"role": "user", "content": user_msg}],
                temperature=0.2,
                max_tokens=int(os.getenv("CHATBOT_MAX_TOKENS", "520")),
            )

            if text:
                return text

            return self._get_fallback_response(user_message)

        except Exception as e:
            print(f"AI response error: {e}")
            return self._get_fallback_response(user_message)

    def _get_fallback_response(self, user_message: str) -> str:
        """Get rule-based fallback response"""
        message_lower = user_message.lower()
        message_norm = re.sub(r"[^a-z0-9\s]", " ", message_lower)
        message_norm = re.sub(r"\s+", " ", message_norm).strip()

        if (
            ("check url" in message_norm)
            or ("check urls" in message_norm)
            or ("scan url" in message_norm)
            or ("scan urls" in message_norm)
        ):
            for k in ("how to check urls", "how to check url"):
                if k in self.fallback_responses:
                    return self.fallback_responses[k]

        # Check for keyword matches
        for key, response in self.fallback_responses.items():
            key_norm = re.sub(r"[^a-z0-9\s]", " ", str(key).lower())
            key_norm = re.sub(r"\s+", " ", key_norm).strip()
            if key_norm and key_norm in message_norm:
                return response

        # Default response
        return self.fallback_responses["default"]

    def explain_scan_result(self, scan_data: Dict) -> str:
        """
        Generate explanation for scan results

        Args:
            scan_data: Scan result dictionary

        Returns:
            Human-friendly explanation
        """
        threat_score = scan_data.get("threat_score", 0)
        threat_level = scan_data.get("threat_level", "unknown")

        context = {
            "scan_result": {
                "url": scan_data.get("url", "N/A"),
                "threat_score": threat_score,
                "threat_level": threat_level,
                "is_safe": scan_data.get("is_safe", False),
                "detections": scan_data.get("detections", {}),
            }
        }

        prompt = "Explain this scan result to a non-technical user in 2-3 sentences. What does it mean and what should they do?"

        return self.get_response(prompt, context)

    def get_conversation_starters(self) -> List[str]:
        """Get suggested questions users can ask"""
        return [
            "How does WebShield's multi-engine detection work?",
            "What is phishing and how do you detect it?",
            "How do I scan a URL for threats?",
            "What do threat scores mean?",
            "How to check URL's",
            "How to check URL",
            "How accurate is your AI detection?",
            "What is SSL certificate validation?",
            "Tell me about the browser extension",
            "What are WebShield's key features?",
            "How does typosquatting detection work?",
            "What is VirusTotal integration?",
            "Explain your machine learning models",
            "What are the different types of cyber threats?",
            "What should I do if a site is flagged dangerous?",
        ]


# Singleton instance
_chatbot_instance = None


def get_chatbot() -> WebShieldChatbot:
    """Get or create chatbot instance"""
    global _chatbot_instance
    if _chatbot_instance is None:
        _chatbot_instance = WebShieldChatbot()
    return _chatbot_instance
