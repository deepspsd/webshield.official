"""
WebShield Chatbot Assistant
AI-powered help system for users to understand security features and scan results
"""

import json
import os
from typing import Dict, List, Optional

import google.generativeai as genai


class WebShieldChatbot:
    """AI-powered chatbot assistant for WebShield"""

    def __init__(self, api_key: Optional[str] = None):
        """Initialize chatbot with Gemini API"""
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel("gemini-pro")
            self.use_ai = True
        else:
            self.use_ai = False
            print("Warning: No Gemini API key found. Using fallback responses.")

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

        # Fallback responses for common questions
        self.fallback_responses = {
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
        else:
            return self._get_fallback_response(user_message)

    def _get_ai_response(self, user_message: str, context: Optional[Dict] = None) -> str:
        """Get AI-powered response using Gemini"""
        try:
            # Build prompt with context
            prompt = f"{self.system_context}\n\n"

            if context:
                prompt += f"Context: {json.dumps(context, indent=2)}\n\n"

            prompt += f"User Question: {user_message}\n\nAssistant:"

            # Generate response
            response = self.model.generate_content(prompt)

            # Extract text from response
            if response and response.text:
                return response.text.strip()
            else:
                return self._get_fallback_response(user_message)

        except Exception as e:
            print(f"AI response error: {e}")
            return self._get_fallback_response(user_message)

    def _get_fallback_response(self, user_message: str) -> str:
        """Get rule-based fallback response"""
        message_lower = user_message.lower()

        # Check for keyword matches
        for key, response in self.fallback_responses.items():
            if key in message_lower:
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
            "How accurate is your AI detection?",
            "What is SSL certificate validation?",
            "Tell me about the browser extension",
            "What are WebShield's key features?",
            "How does typosquatting detection work?",
            "What is VirusTotal integration?",
            "Explain your machine learning models",
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
