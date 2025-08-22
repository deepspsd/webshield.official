import aiohttp
import re
import urllib.parse
import base64
import asyncio
import logging
import os
from typing import Dict, Any

logger = logging.getLogger(__name__)

# VirusTotal API configuration
VT_API_KEY = os.getenv('VT_API_KEY')
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Whitelist of known legitimate domains to prevent false positives
LEGITIMATE_DOMAINS = [
    'github.com', 'www.github.com', 'github.io', 'www.github.io',
    'youtube.com', 'www.youtube.com', 'youtu.be', 'www.youtu.be',
    'google.com', 'www.google.com', 'gmail.com', 'www.gmail.com',
    'facebook.com', 'www.facebook.com', 'instagram.com', 'www.instagram.com',
    'twitter.com', 'www.twitter.com', 'x.com', 'www.x.com',
    'amazon.com', 'www.amazon.com', 'amazon.co.uk', 'www.amazon.co.uk',
    'microsoft.com', 'www.microsoft.com', 'outlook.com', 'www.outlook.com',
    'apple.com', 'www.apple.com', 'icloud.com', 'www.icloud.com',
    'netflix.com', 'www.netflix.com', 'ebay.com', 'www.ebay.com',
    'paypal.com', 'www.paypal.com', 'stackoverflow.com', 'www.stackoverflow.com',
    'reddit.com', 'www.reddit.com', 'linkedin.com', 'www.linkedin.com',
    'wikipedia.org', 'www.wikipedia.org', 'wikipedia.com', 'www.wikipedia.com',
    'mozilla.org', 'www.mozilla.org', 'firefox.com', 'www.firefox.com',
    'chrome.com', 'www.chrome.com', 'brave.com', 'www.brave.com',
    'discord.com', 'www.discord.com', 'slack.com', 'www.slack.com',
    'zoom.us', 'www.zoom.us', 'teams.microsoft.com', 'www.teams.microsoft.com',
    'dropbox.com', 'www.dropbox.com', 'drive.google.com', 'www.drive.google.com',
    'onedrive.live.com', 'www.onedrive.live.com'
]

class WebShieldDetector:
    def __init__(self):
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze_url_patterns(self, url: str) -> Dict[str, Any]:
        """Analyze URL patterns for suspicious characteristics"""
        try:
            # Try to use ML analysis first
            ml_result = await self._analyze_url_ml(url)
            if ml_result and ml_result.get('ml_enabled', False):
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
            result = ml_engine.analyze_url_ml(url)
            
            if result.get('ml_enabled', False):
                logger.info(f"ML URL analysis successful for {url}")
                # Extract and calibrate values
                threat_prob = float(result.get('threat_probability', 0.0))
                prediction = int(result.get('prediction', 0))
                confidence = float(result.get('confidence', 0.0))
                domain = url.split('/')[2] if '//' in url else url

                # Trusted domain override
                if domain in LEGITIMATE_DOMAINS:
                    return {
                        'suspicious_score': 0,
                        'detected_issues': ['Legitimate domain whitelisted'],
                        'domain': domain,
                        'is_suspicious': False,
                        'ml_enabled': True,
                        'ml_confidence': max(confidence, 0.95)
                    }

                # Conservative calibration for score
                if threat_prob <= 0.6:
                    calibrated_score = 0
                else:
                    calibrated_score = int(((threat_prob - 0.6) / 0.4) * 100)

                is_suspicious = prediction == 1 and calibrated_score >= 20

                return {
                    'suspicious_score': calibrated_score,
                    'detected_issues': result.get('detected_issues', []),
                    'domain': domain,
                    'is_suspicious': is_suspicious,
                    'ml_enabled': True,
                    'ml_confidence': confidence
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
                    'suspicious_score': 0,
                    'detected_issues': ['Legitimate domain whitelisted'],
                    'domain': domain,
                    'is_suspicious': False,
                    'ml_enabled': False
                }
            
            # Basic suspicious pattern detection
            suspicious_score = 0
            detected_issues = []
            
            # Check for suspicious TLDs
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club']
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                suspicious_score += 10
                detected_issues.append(f"Suspicious TLD: {domain.split('.')[-1]}")
            
            # Check for IP addresses instead of domain names
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                suspicious_score += 15
                detected_issues.append("IP address instead of domain name")
            
            # Check for excessive subdomains
            subdomain_count = len(domain.split('.')) - 1
            if subdomain_count > 3:
                suspicious_score += 8
                detected_issues.append(f"Excessive subdomains: {subdomain_count}")
            
            # Check for suspicious keywords in domain - only flag when combined with other suspicious patterns
            suspicious_keywords = ['secure', 'login', 'signin', 'bank', 'paypal', 'amazon', 'google', 'facebook']
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
                'suspicious_score': suspicious_score,
                'detected_issues': detected_issues,
                'domain': domain,
                'is_suspicious': suspicious_score > 20,
                'ml_enabled': False
            }
        except Exception as e:
            logger.error(f"Rule-based URL analysis failed for {url}: {e}")
            return {
                'suspicious_score': 0,
                'detected_issues': [f"Analysis error: {str(e)}"],
                'domain': 'unknown',
                'is_suspicious': False,
                'ml_enabled': False
            }
    
    async def analyze_ssl_certificate(self, url: str) -> Dict[str, Any]:
        """Analyze SSL certificate validity with proper certificate details"""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != 'https':
            return {
                'valid': False,
                'error': 'No HTTPS',
                'details': 'Site does not use HTTPS encryption',
                'threat_score': 25,
                'is_intentionally_insecure': False,
                'issuer': 'N/A',
                'expires': 'N/A'
            }
        
        try:
            import ssl
            import socket
            from datetime import datetime

            hostname = parsed.hostname
            port = parsed.port or 443

            # Use a context that does NOT disable verification (to get real certs)
            context = ssl.create_default_context()
            # context.check_hostname = False
            # context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
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
                        issuer_dict = _flatten_name(cert.get('issuer', ()))
                        issuer_parts = []
                        if issuer_dict.get('commonName'):
                            issuer_parts.append(f"CN={issuer_dict.get('commonName')}")
                        if issuer_dict.get('organizationName'):
                            issuer_parts.append(f"O={issuer_dict.get('organizationName')}")
                        if issuer_dict.get('countryName'):
                            issuer_parts.append(f"C={issuer_dict.get('countryName')}")
                        if issuer_dict.get('organizationalUnitName'):
                            issuer_parts.append(f"OU={issuer_dict.get('organizationalUnitName')}")
                        issuer = ", ".join(issuer_parts) if issuer_parts else "Unknown"

                        expires = "Unknown"
                        threat_score = 0
                        valid = True
                        if 'notAfter' in cert:
                            try:
                                date_str = cert['notAfter']
                                if 'GMT' in date_str:
                                    expire_date = datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
                                else:
                                    expire_date = datetime.strptime(date_str, '%b %d %H:%M:%S %Y')
                                expires = expire_date.strftime('%Y-%m-%d %H:%M:%S UTC')
                                now = datetime.utcnow()
                                if expire_date < now:
                                    threat_score = 30
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
                        subject_dict = _flatten_name(cert.get('subject', ()))
                        if subject_dict.get('commonName') and issuer_dict.get('commonName') and subject_dict.get('commonName') == issuer_dict.get('commonName'):
                            is_self_signed = True
                            threat_score += 10

                        return {
                            'valid': valid,
                            'issuer': issuer,
                            'expires': expires,
                            'threat_score': threat_score,
                            'is_intentionally_insecure': False,
                            'is_self_signed': is_self_signed,
                            'details': 'SSL certificate analyzed successfully'
                        }
                    else:
                        return {
                            'valid': False,
                            'error': 'No certificate found',
                            'details': 'Could not retrieve SSL certificate',
                            'threat_score': 20,
                            'is_intentionally_insecure': False,
                            'issuer': 'N/A',
                            'expires': 'N/A'
                        }
        except ssl.SSLError as e:
            logger.warning(f"SSL error for {url}: {e}")
            return {
                'valid': False,
                'error': f'SSL Error: {str(e)}',
                'details': 'SSL certificate validation failed',
                'threat_score': 15,
                'is_intentionally_insecure': False,
                'issuer': 'N/A',
                'expires': 'N/A'
            }
        except socket.timeout:
            logger.warning(f"SSL connection timeout for {url}")
            return {
                'valid': False,
                'error': 'Connection timeout',
                'details': 'SSL connection timed out',
                'threat_score': 10,
                'is_intentionally_insecure': False,
                'issuer': 'N/A',
                'expires': 'N/A'
            }
        except Exception as e:
            logger.warning(f"SSL analysis failed for {url}: {e}")
            return {
                'valid': False,
                'error': f'Connection failed: {str(e)}',
                'details': 'Could not establish SSL connection',
                'threat_score': 10,
                'is_intentionally_insecure': False,
                'issuer': 'N/A',
                'expires': 'N/A'
            }
    
    async def analyze_content(self, url: str, max_bytes=200*1024) -> Dict[str, Any]:
        """Analyze webpage content for phishing indicators"""
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            async with aiohttp.ClientSession(connector=connector, headers=headers) as content_session:
                async with content_session.get(url, timeout=5.0) as response:
                    if response.status != 200:
                        return {
                            'error': f'HTTP {response.status}', 
                            'phishing_score': 0,
                            'detected_indicators': [],
                            'is_suspicious': False,
                            'content_length': 0,
                            'ml_enabled': False
                        }
                    
                    content = await response.content.read(max_bytes)
                    content = content.decode(errors='ignore')
                    
                    # Try ML analysis first
                    ml_result = await self._analyze_content_ml(content)
                    if ml_result and ml_result.get('ml_enabled', False):
                        return ml_result
                    
                    # Fallback to rule-based analysis
                    return await self._rule_based_content_analysis(content)
                    
        except Exception as e:
            return {
                'error': f'Content analysis failed: {str(e)}',
                'phishing_score': 0,
                'detected_indicators': [],
                'is_suspicious': False,
                'content_length': 0,
                'ml_enabled': False
            }
    
    async def analyze_text_content(self, text_content: str) -> Dict[str, Any]:
        """Analyze raw text content using ML models"""
        try:
            # Try ML analysis first
            ml_result = await self._analyze_content_ml(text_content)
            if ml_result and ml_result.get('ml_enabled', False):
                return ml_result
            
            # Fallback to rule-based analysis
            return await self._rule_based_content_analysis(text_content)
            
        except Exception as e:
            return {
                'error': f'Text content analysis failed: {str(e)}',
                'phishing_score': 0,
                'detected_indicators': [],
                'is_suspicious': False,
                'content_length': 0,
                'ml_enabled': False
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
            result = ml_engine.analyze_content_ml(html_content)
            
            logger.info(f"ML content analysis result: {result}")
            if result.get('ml_enabled', False):
                logger.info("ML content analysis successful")
                # Convert ML result to expected format
                return {
                    'phishing_score': int(result.get('phishing_probability', 0) * 100),
                    'detected_indicators': result.get('detected_issues', []),  # Use detected_issues from ML
                    'is_suspicious': result.get('threat_detected', False),   # Use threat_detected from ML
                    'content_length': len(html_content),
                    'ml_enabled': True,
                    'ml_confidence': result.get('confidence', 0.0)
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
            'password', 'login', 'signin', 'account', 'verify', 'confirm',
            'bank', 'credit', 'card', 'ssn', 'social security', 'paypal',
            'urgent', 'immediate', 'suspended', 'locked', 'verify now'
        ]
        
        content_lower = html_content.lower()
        for keyword in suspicious_keywords:
            if keyword in content_lower:
                phishing_score += 2
                detected_indicators.append(f"Suspicious keyword: {keyword}")
        
        # Check for forms
        if '<form' in html_content.lower():
            phishing_score += 3
            detected_indicators.append("Contains form")
        
        # Check for input fields
        input_count = html_content.lower().count('<input')
        if input_count > 5:
            phishing_score += 1
            detected_indicators.append(f"Multiple input fields: {input_count}")
        
        # Check for external links
        external_links = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_content)
        if len(external_links) > 10:
            phishing_score += 2
            detected_indicators.append(f"Many external links: {len(external_links)}")
        
        return {
            'phishing_score': phishing_score,
            'detected_indicators': detected_indicators,
            'is_suspicious': phishing_score > 25,
            'content_length': len(html_content),
            'ml_enabled': False
        }
    
    async def check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal API.
        If no cached analysis is available, submit a URL analysis and poll briefly for a result.
        """
        if not VT_API_KEY or VT_API_KEY == 'your_virustotal_api_key_here':
            return {
                'malicious_count': 0,
                'suspicious_count': 0,
                'harmless_count': 1,
                'undetected_count': 0,
                'total_engines': 1,
                'engines_results': {'fallback': {'category': 'harmless', 'result': 'check_failed'}},
                'reputation': 0,
                'cached': False,
                'fallback_checks': True
            }
        
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            headers = {
                'x-apikey': VT_API_KEY,
                'Content-Type': 'application/json'
            }
            
            check_url = f"{VT_BASE_URL}/urls/{url_id}"

            # First try to get cached analysis quickly
            try:
                async with self.session.get(check_url, headers=headers, timeout=2.0) as response:
                    if response.status == 200:
                        data = await response.json()
                        stats = data['data']['attributes']['last_analysis_stats']
                        return {
                            'malicious_count': stats.get('malicious', 0),
                            'suspicious_count': stats.get('suspicious', 0),
                            'harmless_count': stats.get('harmless', 0),
                            'undetected_count': stats.get('undetected', 0),
                            'total_engines': sum(stats.values()),
                            'engines_results': {},
                            'reputation': data['data']['attributes'].get('reputation', 0),
                            'cached': True
                        }
            except Exception:
                pass

            # Submit URL for analysis if not cached
            submit_url = f"{VT_BASE_URL}/urls"
            form = aiohttp.FormData()
            form.add_field('url', url)
            submit_id = None
            try:
                async with self.session.post(submit_url, headers={'x-apikey': VT_API_KEY}, data=form, timeout=3.0) as resp:
                    if resp.status in (200, 202):
                        sub = await resp.json()
                        submit_id = sub.get('data', {}).get('id')
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
                                status = adata.get('data', {}).get('attributes', {}).get('status')
                                if status == 'completed':
                                    # After completion, fetch the URL object again for stats
                                    async with self.session.get(check_url, headers=headers, timeout=2.0) as fresp:
                                        if fresp.status == 200:
                                            fdata = await fresp.json()
                                            stats = fdata['data']['attributes']['last_analysis_stats']
                                            return {
                                                'malicious_count': stats.get('malicious', 0),
                                                'suspicious_count': stats.get('suspicious', 0),
                                                'harmless_count': stats.get('harmless', 0),
                                                'undetected_count': stats.get('undetected', 0),
                                                'total_engines': sum(stats.values()),
                                                'engines_results': {},
                                                'reputation': fdata['data']['attributes'].get('reputation', 0),
                                                'cached': False
                                            }
                    except Exception:
                        pass

            # Fallback if no immediate data available
            return {
                'malicious_count': 0,
                'suspicious_count': 0,
                'harmless_count': 1,
                'undetected_count': 0,
                'total_engines': 1,
                'engines_results': {'fallback': {'category': 'harmless', 'result': 'check_failed'}},
                'reputation': 0,
                'cached': False,
                'fallback_checks': True
            }
        except Exception as e:
            return {
                'malicious_count': 0,
                'suspicious_count': 0,
                'harmless_count': 1,
                'undetected_count': 0,
                'total_engines': 1,
                'engines_results': {'fallback': {'category': 'harmless', 'result': 'check_failed'}},
                'reputation': 0,
                'cached': False,
                'fallback_checks': True,
                'error': f'VirusTotal check failed: {str(e)}'
            }
