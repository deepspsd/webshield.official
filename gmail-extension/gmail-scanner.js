// WebShield Gmail Email Scanner (Standalone Gmail Extension)
// World-Class Phishing & Fake Email Detection
// Version 2.0.0 - Production Build

// ===== PRODUCTION CONFIGURATION =====
const DEBUG_MODE = false; // Set to true for development logging
const RATE_LIMIT_MS = 3000; // Minimum time between scans (3 seconds)
const CACHE_TTL_MS = 300000; // Cache TTL (5 minutes)
const MAX_CACHE_SIZE = 50; // Maximum cached scan results

// Controlled logging - only logs in debug mode
const log = {
  info: (...args) => DEBUG_MODE && console.log('[WebShield]', ...args),
  warn: (...args) => DEBUG_MODE && console.warn('[WebShield]', ...args),
  error: (...args) => console.error('[WebShield]', ...args) // Always log errors
};

/**
 * Escapes HTML characters to prevent XSS attacks when interpolating strings into HTML
 * @param {string|number} str - The string to escape
 * @returns {string} Escaped string
 */
function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Debounces a function execution
 * @param {Function} func - The function to debounce
 * @param {number} wait - The wait time in milliseconds
 * @returns {Function} Debounced function
 */
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

log.info('🛡️ Gmail Scanner loaded');

const DOM_ID_PREFIX = 'gr-gmail-2025';
const ID = {
  shadowHost: `${DOM_ID_PREFIX}-shadow-host`,
  floatOverlay: `${DOM_ID_PREFIX}-float-overlay`,
  floatCard: `${DOM_ID_PREFIX}-float-card`,
  badgeCloseBtn: `${DOM_ID_PREFIX}-close-btn`,
  badgeDetails: `${DOM_ID_PREFIX}-details`,
  badgeToggleDetails: `${DOM_ID_PREFIX}-toggle-details`,
  scanBtn: `${DOM_ID_PREFIX}-scan-btn`,
  scanBtnWrap: `${DOM_ID_PREFIX}-scan-btn-wrap`,
  copyBadgeBtn: `${DOM_ID_PREFIX}-copy-badge`,
  testLinkBtn: `${DOM_ID_PREFIX}-test-link`,
  floatingScanBtn: `${DOM_ID_PREFIX}-float-scan-btn`
};

const MSG = {
  scanEmailMetadata: 'GMAIL_EXT_SCAN_EMAIL_METADATA',
  storeLastScan: 'GMAIL_EXT_STORE_LAST_EMAIL_SCAN',
  dangerousEmailDetected: 'GMAIL_EXT_DANGEROUS_EMAIL_DETECTED',
  scanEmailManual: 'GMAIL_EXT_SCAN_EMAIL_MANUAL',
  safetyAction: 'GMAIL_EXT_SAFETY_ACTION'
};

const WEBSHIELD_CONFIG = {
  autoScan: false,
  scanDelay: 1200,
  useShadowDOM: true
};

const LAST_SCAN_KEY = 'webshield_gmail_last_scan';

// State management
let isScanning = false;
let manualScanInProgress = false;
let lastScanTime = 0; // Rate limiting
let scanCache = new Map(); // Cache scan results to avoid duplicate API calls
let activeScanRunId = 0;

// ===== ERROR BOUNDARY - Safe DOM Operations =====

/**
 * Safely query a DOM element with error handling
 * @param {string} selector - CSS selector
 * @param {Element} context - Optional context element
 * @returns {Element|null}
 */
function safeQuery(selector, context = document) {
  try {
    return context.querySelector(selector);
  } catch (e) {
    log.warn('DOM query failed:', selector, e.message);
    return null;
  }
}

/**
 * Safely query all matching DOM elements with error handling
 * @param {string} selector - CSS selector
 * @param {Element} context - Optional context element
 * @returns {NodeList}
 */
function safeQueryAll(selector, context = document) {
  try {
    return context.querySelectorAll(selector);
  } catch (e) {
    log.warn('DOM queryAll failed:', selector, e.message);
    return [];
  }
}

/**
 * Safely get element attribute with error handling
 * @param {Element} el - DOM element
 * @param {string} attr - Attribute name
 * @returns {string|null}
 */
function safeGetAttr(el, attr) {
  try {
    return el?.getAttribute(attr) || null;
  } catch (e) {
    return null;
  }
}

/**
 * Check if rate limit allows scanning
 * @returns {boolean}
 */
function canScan() {
  const now = Date.now();
  if (now - lastScanTime < RATE_LIMIT_MS) {
    log.info('Rate limited - please wait');
    return false;
  }
  return true;
}

/**
 * Update last scan timestamp for rate limiting
 */
function updateScanTimestamp() {
  lastScanTime = Date.now();
}


// Homograph attack detection - Cyrillic and lookalike characters
const HOMOGRAPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'і': 'i', 'ј': 'j', 'ѕ': 's',
  'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', 'ο': 'o', 'ϲ': 'c', 'ν': 'v',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b',
  'ℓ': 'l', 'ꭱ': 'r', 'ꮪ': 's', 'ꭺ': 'a'
};

function detectHomographAttack(text) {
  const suspicious = [];
  for (const char of text) {
    if (HOMOGRAPH_MAP[char]) {
      suspicious.push({ char, looksLike: HOMOGRAPH_MAP[char] });
    }
  }
  return suspicious.length > 0 ? { isHomograph: true, chars: suspicious } : { isHomograph: false };
}

// Trusted domains that don't need strict authentication checks in the UI (assumed valid if Gmail didn't flag them)
const HIGH_TRUST_DOMAINS = new Set([
  'gmail.com', 'google.com', 'youtube.com', 'accounts.google.com'
]);

// Suspicious phishing keywords with categories and severity
const PHISHING_KEYWORDS = {
  urgency: [
    'urgent', 'immediately', 'right away', 'act now', 'expires today',
    'limited time', 'deadline', 'within 24 hours', 'within 48 hours',
    'last chance', 'final warning', 'action required', 'respond immediately'
  ],
  fear: [
    'suspended', 'blocked', 'disabled', 'compromised', 'unauthorized',
    'unusual activity', 'security alert', 'fraud alert', 'locked',
    'terminated', 'deleted', 'hacked', 'breach', 'stolen'
  ],
  verification: [
    'verify your account', 'confirm your identity', 'update your information',
    'validate your account', 'verify your email', 'confirm your details',
    'update your payment', 'verify your payment', 'confirm ownership'
  ],
  financial: [
    'wire transfer', 'western union', 'moneygram', 'gift card',
    'bitcoin', 'cryptocurrency', 'payment failed', 'invoice attached',
    'outstanding balance', 'overdue payment', 'refund pending'
  ],
  impersonation: [
    'from the desk of', 'official notice', 'legal department',
    'customer service', 'technical support', 'help desk',
    'account team', 'security team', 'fraud department'
  ],
  prizes: [
    'congratulations', 'you have won', 'lottery', 'jackpot',
    'claim your prize', 'winner', 'selected', 'lucky'
  ]
};

function analyzePhishingKeywords(text) {
  const lowerText = text.toLowerCase();
  const detected = { total: 0, categories: {}, keywords: [] };

  for (const [category, keywords] of Object.entries(PHISHING_KEYWORDS)) {
    detected.categories[category] = 0;
    for (const keyword of keywords) {
      if (lowerText.includes(keyword)) {
        detected.total++;
        detected.categories[category]++;
        detected.keywords.push({ keyword, category });
      }
    }
  }

  return detected;
}

// Known trusted domains (major email providers and services)
const TRUSTED_DOMAINS = new Set([
  'google.com', 'gmail.com', 'microsoft.com', 'outlook.com', 'live.com',
  'apple.com', 'icloud.com', 'amazon.com', 'facebook.com', 'meta.com',
  'twitter.com', 'x.com', 'linkedin.com', 'github.com', 'netflix.com',
  'paypal.com', 'stripe.com', 'shopify.com', 'zoom.us', 'slack.com',
  'dropbox.com', 'adobe.com', 'salesforce.com', 'spotify.com', 'uber.com'
]);

// Domains commonly impersonated
const IMPERSONATED_DOMAINS = [
  'paypal', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
  'facebook', 'instagram', 'bank', 'chase', 'wellsfargo', 'bofa',
  'citibank', 'usps', 'fedex', 'ups', 'dhl', 'irs', 'gov'
];

// URL shorteners to flag
const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in', 'db.tt', 'qr.ae',
  'bitly.com', 'cutt.ly', 'rb.gy', 'shorturl.at'
];

function analyzeURL(url) {
  const analysis = {
    isSuspicious: false,
    reasons: [],
    riskScore: 0
  };

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname.toLowerCase();

    // Check for IP-based URL
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      analysis.isSuspicious = true;
      analysis.reasons.push('IP address instead of domain name');
      analysis.riskScore += 40;
    }

    // Check for URL shorteners
    if (URL_SHORTENERS.some(s => hostname.includes(s))) {
      analysis.isSuspicious = true;
      analysis.reasons.push('URL shortener detected');
      analysis.riskScore += 20;
    }

    // Check for homograph attacks in domain
    const homograph = detectHomographAttack(hostname);
    if (homograph.isHomograph) {
      analysis.isSuspicious = true;
      analysis.reasons.push('Suspicious lookalike characters in domain');
      analysis.riskScore += 50;
    }

    // Check for domain impersonation (e.g., paypa1.com, amaz0n.com)
    for (const brand of IMPERSONATED_DOMAINS) {
      const cleanHost = hostname.replace(/[0-9]/g, '').replace(/-/g, '');
      if (cleanHost.includes(brand) && !TRUSTED_DOMAINS.has(hostname)) {
        analysis.isSuspicious = true;
        analysis.reasons.push(`Possible ${brand} impersonation`);
        analysis.riskScore += 45;
        break;
      }
    }

    // Check for excessive subdomains (e.g., login.secure.paypal.suspicious.com)
    const subdomains = hostname.split('.').length - 2;
    if (subdomains > 3) {
      analysis.isSuspicious = true;
      analysis.reasons.push('Excessive subdomains');
      analysis.riskScore += 15;
    }

    // Check for suspicious TLDs
    const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click'];
    if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
      analysis.isSuspicious = true;
      analysis.reasons.push('Suspicious top-level domain');
      analysis.riskScore += 25;
    }

    // Check for login/password in path
    if (/login|signin|password|credential|secure|verify|update|confirm/i.test(path)) {
      analysis.riskScore += 10;
    }

    // Check for data: URI (XSS risk)
    if (url.startsWith('data:')) {
      analysis.isSuspicious = true;
      analysis.reasons.push('Data URI detected (potential XSS)');
      analysis.riskScore += 60;
    }

    // Check for javascript: URI
    if (url.startsWith('javascript:')) {
      analysis.isSuspicious = true;
      analysis.reasons.push('JavaScript URI detected');
      analysis.riskScore += 70;
    }

    // Check URL length (phishing URLs tend to be very long)
    if (url.length > 150) {
      analysis.riskScore += 10;
    }

    // Check for @ symbol (credential confusion)
    if (url.includes('@') && !url.startsWith('mailto:')) {
      analysis.isSuspicious = true;
      analysis.reasons.push('@ symbol in URL (credential confusion attack)');
      analysis.riskScore += 40;
    }

  } catch (e) {
    // Invalid URL
    analysis.riskScore += 5;
  }

  return analysis;
}

function analyzeSenderEmail(email) {
  const analysis = {
    isSuspicious: false,
    reasons: [],
    riskScore: 0,
    domain: null,
    isTrusted: false
  };

  if (!email || !email.includes('@')) return analysis;

  const [localPart, domain] = email.toLowerCase().split('@');
  analysis.domain = domain;

  // Check if from trusted domain
  if (TRUSTED_DOMAINS.has(domain)) {
    analysis.isTrusted = true;
    return analysis;
  }

  // Check for homograph attacks in domain
  const homograph = detectHomographAttack(domain);
  if (homograph.isHomograph) {
    analysis.isSuspicious = true;
    analysis.reasons.push('Suspicious lookalike characters in sender domain');
    analysis.riskScore += 50;
  }

  // Check for domain impersonation
  for (const brand of IMPERSONATED_DOMAINS) {
    if (domain.includes(brand) && !TRUSTED_DOMAINS.has(domain)) {
      analysis.isSuspicious = true;
      analysis.reasons.push(`Sender domain may be impersonating ${brand}`);
      analysis.riskScore += 40;
      break;
    }
  }

  // Check for suspicious patterns in local part
  if (/^(noreply|no-reply|donotreply|admin|support|security|alert)/i.test(localPart)) {
    // These are common in both legitimate and phishing emails
    analysis.riskScore += 5;
  }

  // Check for random-looking local parts (common in spam)
  if (/^[a-z0-9]{20,}$/i.test(localPart)) {
    analysis.isSuspicious = true;
    analysis.reasons.push('Random-looking sender address');
    analysis.riskScore += 20;
  }

  // Check for recently registered TLDs commonly used in phishing
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top'];
  if (suspiciousTLDs.some(tld => domain.endsWith(tld))) {
    analysis.isSuspicious = true;
    analysis.reasons.push('Sender uses suspicious domain extension');
    analysis.riskScore += 30;
  }

  return analysis;
}

// Calculate client-side threat score
function calculateClientSideThreatScore(metadata) {
  let score = 0;
  const flags = [];

  // Analyze sender
  if (metadata.sender_email) {
    const senderAnalysis = analyzeSenderEmail(metadata.sender_email);
    score += senderAnalysis.riskScore;
    flags.push(...senderAnalysis.reasons);
  }

  // Analyze subject for phishing keywords
  if (metadata.subject) {
    const subjectAnalysis = analyzePhishingKeywords(metadata.subject);
    score += subjectAnalysis.total * 5;
    if (subjectAnalysis.total > 2) {
      flags.push(`Subject contains ${subjectAnalysis.total} phishing keywords`);
    }
  }

  // Analyze links
  if (metadata.links && metadata.links.length > 0) {
    let linkScore = 0;
    let suspiciousLinkCount = 0;

    for (const link of metadata.links) {
      const linkAnalysis = analyzeURL(link);
      if (linkAnalysis.isSuspicious) {
        suspiciousLinkCount++;
        // Diminishing returns for multiple links to prevents score explosion
        linkScore += Math.max(5, linkAnalysis.riskScore / (1 + (suspiciousLinkCount * 0.5)));
      }
    }

    // Cap total link score contribution
    score += Math.min(linkScore, 45);

    if (suspiciousLinkCount > 0) {
      flags.push(`${suspiciousLinkCount} suspicious link(s) detected`);
    }
  }

  // Check for dangerous attachments
  if (metadata.has_dangerous_attachments) {
    score += 40;
    flags.push('Dangerous attachment type detected');
  }

  // Check for "via" header (indicates different sending server)
  if (metadata.headers?.via_warning) {
    score += 15;
    flags.push('Email sent via different server than claimed');
  }

  return {
    clientScore: Math.min(score, 100),
    clientFlags: flags
  };
}

// --- Helper Functions ---

function clickGmailMenuItem(text) {
  const moreBtn = document.querySelector('[aria-label="More actions"]')
    || document.querySelector('[data-tooltip="More actions"]');
  if (moreBtn) {
    moreBtn.click();
    setTimeout(() => {
      const items = Array.from(document.querySelectorAll('div[role="menuitem"], span'));
      const item = items.find(s => s.textContent.trim() === text);
      if (item) {
        item.click();
        // Close menu if it didn't auto close? usually click does it.
      }
    }, 100);
    return true;
  }
  return false;
}

function findUnsubscribeLink() {
  // 1. Native Header Unsubscribe
  const headerUnsub = document.querySelector('.ca');
  if (headerUnsub) return headerUnsub;

  // 2. Link in body
  const links = Array.from(document.querySelectorAll('a'));
  return links.find(a => a.textContent.toLowerCase().includes('unsubscribe'));
}

// ... [storageLocalSet, runtimeSendMessage, getCurrentEmailId same as before] ...

function storageLocalSet(items) {
  return new Promise((resolve) => {
    try {
      chrome.storage.local.set(items, () => {
        resolve();
      });
    } catch (e) {
      resolve();
    }
  });
}

function runtimeSendMessage(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        resolve(response);
      });
    } catch (e) {
      resolve(undefined);
    }
  });
}

function getCurrentEmailId() {
  const hash = window.location.hash;
  const match = hash.match(/\/([A-Za-z0-9_-]+)$/);
  if (match && match[1].length > 5) return match[1];
  return null;
}

function storeLastScanResult(scanResult, source = 'content') {
  try {
    const emailId = getCurrentEmailId();
    const payload = {
      scanResult,
      source,
      emailId,
      url: window.location.href,
      timestamp: Date.now()
    };
    const storageItems = { [LAST_SCAN_KEY]: payload };
    if (emailId) {
      storageItems[`gmail_report_${emailId}`] = payload;
    }
    storageLocalSet(storageItems);
    runtimeSendMessage({ type: MSG.storeLastScan, payload });
  } catch (_) { }
}

function extractEmailMetadata() {
  try {
    // Enhanced sender detection with multiple fallback selectors
    let senderEmail = null;
    let senderName = null;

    // Primary: Gmail's sender element with email attribute
    const senderSelectors = [
      'span.gD[email]',
      '.gD[email]',
      'span[email]',
      '[data-hovercard-id]',
      '.go[email]',
      'span.g2[email]'
    ];

    for (const selector of senderSelectors) {
      const el = document.querySelector(selector);
      if (el) {
        const email = el.getAttribute('email') || el.getAttribute('data-hovercard-id');
        if (email && email.includes('@')) {
          senderEmail = email;
          break;
        }
      }
    }

    // Secondary: Search for email in title attribute of sender name
    if (!senderEmail) {
      const titleSelectors = ['.gD', '.go', 'span[name]'];
      for (const sel of titleSelectors) {
        const el = document.querySelector(sel);
        if (el) {
          const title = el.getAttribute('title') || el.getAttribute('name');
          if (title && title.includes('@')) {
            const match = title.match(/[\w.-]+@[\w.-]+\.\w+/);
            if (match) { senderEmail = match[0]; break; }
          }
        }
      }
    }

    // Fallback: Parse from email header area
    if (!senderEmail) {
      const headerText = document.querySelector('.gE')?.textContent || '';
      const emailMatch = headerText.match(/[\w.-]+@[\w.-]+\.\w+/);
      if (emailMatch) senderEmail = emailMatch[0];
    }

    // Sender name extraction
    const nameSelectors = [
      'span.go',
      '.go',
      'span.gD',
      '.gD',
      '[data-hovercard-owner-id]'
    ];

    for (const selector of nameSelectors) {
      const el = document.querySelector(selector);
      if (el) {
        const name = el.textContent?.trim();
        if (name && name.length > 0 && !name.includes('@')) {
          senderName = name;
          break;
        }
      }
    }

    // Subject extraction with multiple selectors
    const subjectSelectors = [
      'h2.hP',
      '.hP',
      'h2[data-legacy-thread-id]',
      '[data-thread-perm-id]',
      '.aYF > span'
    ];

    let subject = null;
    for (const selector of subjectSelectors) {
      const el = document.querySelector(selector);
      if (el?.textContent?.trim()) {
        subject = el.textContent.trim();
        break;
      }
    }

    // Enhanced link extraction from email body
    const links = new Set();
    const emailBodySelectors = ['.a3s', '.ii.gt', '.gmail_quote', '[data-message-id] .a3s'];

    const normalizeUrl = (u) => {
      if (!u || typeof u !== 'string') return null;
      let s = u.trim();
      if (!s) return null;
      if (s.startsWith('www.')) s = 'https://' + s;
      // Trim common trailing punctuation from plain-text URLs
      s = s.replace(/[\s\)\]\}\>\"\'\,\.;:]+$/g, '');
      // Drop obvious non-web links
      if (/^(mailto:|tel:|javascript:|data:)/i.test(s)) return null;
      try {
        const parsed = new URL(s);
        if (!parsed.hostname) return null;
        return parsed.toString();
      } catch (_) {
        return null;
      }
    };

    for (const selector of emailBodySelectors) {
      const body = document.querySelector(selector);
      if (body) {
        // Anchor links
        body.querySelectorAll('a[href]').forEach(a => {
          const href = a.getAttribute('href');
          if (!href) return;
          let candidate = href;
          // Handle Google's redirect URLs
          if (href.includes('google.com/url?')) {
            const urlParams = new URLSearchParams(href.split('?')[1]);
            candidate = urlParams.get('q') || urlParams.get('url') || href;
          }
          const nu = normalizeUrl(candidate);
          if (nu) links.add(nu);
        });

        // Plain-text URLs (Gmail often renders some URLs as text)
        const text = body.textContent || '';
        const urlMatches = text.match(/\bhttps?:\/\/[^\s<>"]+|\bwww\.[^\s<>"]+/gi) || [];
        for (const m of urlMatches) {
          const nu = normalizeUrl(m);
          if (nu) links.add(nu);
        }

        break; // Found body, no need to continue
      }
    }

    // Header analysis - try to extract SPF/DKIM/DMARC from "Show Original"
    const headers = { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' };

    // Check for "via" indicator (shows if sender is using different server)
    const viaElement = document.querySelector('span.gD[aria-label*="via"]')
      || document.querySelector('[aria-label*="via"]')
      || document.querySelector('.gE span[title*="via"]');

    if (viaElement) {
      const viaText = viaElement.textContent || viaElement.getAttribute('aria-label') || '';
      headers.via = viaText;
      // If sent via different server, might be suspicious
      if (viaText.toLowerCase().includes('via')) {
        headers.via_warning = true;
      }
    }

    // Check for security indicators
    const securityIcon = document.querySelector('.aai img[alt*="lock"]')
      || document.querySelector('.aZo img')
      || document.querySelector('[data-tooltip*="encrypted"]');

    if (securityIcon) {
      headers.encrypted = true;
    }

    // Attachment detection
    const attachments = [];
    const attachmentSelectors = [
      '.aQH', // Attachment container
      '.aZo', // Attachment icon
      '[download]', // Download links
      '.aV3' // Attachment preview
    ];

    document.querySelectorAll('.aQH, .aV3, [download]').forEach(att => {
      const name = att.getAttribute('download') || att.textContent?.trim() || 'attachment';
      const ext = name.split('.').pop()?.toLowerCase();
      attachments.push({ name, extension: ext });
    });

    // Check for dangerous attachment types (expanded list)
    const dangerousExts = [
      'exe', 'bat', 'cmd', 'scr', 'js', 'vbs', 'ps1', 'msi', 'dll',
      'pif', 'application', 'gadget', 'msc', 'hta', 'cpl', 'msp',
      'com', 'jar', 'wsf', 'wsh', 'reg', 'lnk', 'inf', 'scf'
    ];
    const hasDangerousAttachment = attachments.some(a => dangerousExts.includes(a.extension));

    // Extract email body text for content analysis
    let bodyText = '';
    for (const selector of emailBodySelectors) {
      const body = document.querySelector(selector);
      if (body) {
        bodyText = body.textContent?.trim() || '';
        break;
      }
    }

    // Check for reply-to vs from mismatch (common phishing technique)
    let replyToMismatch = false;
    let replyToEmail = null;
    const replyToEl = document.querySelector('[data-reply-to]')
      || document.querySelector('.ajy') // Reply-to container
      || document.querySelector('span[data-hovercard-id]');

    // Try to find reply-to in "Show details" area
    const detailsArea = document.querySelector('.ajH');
    if (detailsArea) {
      const text = detailsArea.textContent || '';
      const replyMatch = text.match(/reply-to:\s*(\S+@\S+)/i);
      if (replyMatch) {
        replyToEmail = replyMatch[1];
        if (replyToEmail && senderEmail && replyToEmail.toLowerCase() !== senderEmail.toLowerCase()) {
          replyToMismatch = true;
        }
      }
    }

    // Enhanced link extraction with display text for text/URL mismatch detection
    const linkDetails = [];
    for (const selector of emailBodySelectors) {
      const body = document.querySelector(selector);
      if (body) {
        body.querySelectorAll('a[href]').forEach(a => {
          const href = a.getAttribute('href');
          const displayText = a.textContent?.trim() || '';
          if (href) {
            let actualUrl = href;
            // Handle Google's redirect URLs
            if (href.includes('google.com/url?')) {
              const urlParams = new URLSearchParams(href.split('?')[1]);
              actualUrl = urlParams.get('q') || urlParams.get('url') || href;
            }

            // Normalize www.* URLs so they are consistently scanned
            if (actualUrl && actualUrl.startsWith('www.')) {
              actualUrl = 'https://' + actualUrl;
            }

            // Check for text/URL mismatch (e.g., text says "paypal.com" but URL is different)
            // This is a major phishing indicator but needs careful handling to avoid false positives
            const textLooksLikeUrl = /^(https?:\/\/)?[\w.-]+\.[a-z]{2,}/i.test(displayText);
            let textUrlMismatch = false;
            if (textLooksLikeUrl && displayText.length > 5) {
              try {
                // Normalize both URLs for comparison
                let displayDomain = displayText.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
                displayDomain = displayDomain.replace(/^www\./, ''); // Remove www prefix

                const actualUrlObj = new URL(actualUrl);
                let actualDomain = actualUrlObj.hostname.toLowerCase();
                actualDomain = actualDomain.replace(/^www\./, ''); // Remove www prefix

                // Skip Google tracking URLs - these wrap legitimate URLs for click tracking
                // The actual destination should match what's displayed
                const isGoogleTrackingUrl = href.includes('google.com/url?') ||
                  actualUrl.includes('google.com/url?') ||
                  actualDomain.includes('google.com');

                // Skip if display text is not actually a domain (might be button text with URL-like chars)
                const displayLooksLikeDomain = /^[\w.-]+\.(com|org|net|io|co|me|gov|edu|info|biz)$/i.test(displayDomain);

                // Trusted redirect services that should not trigger mismatch
                const trustedRedirects = ['google.com', 'outlook.office365.com', 'safelinks.protection.outlook.com',
                  'nam12.safelinks.protection.outlook.com', 'links.e.twitch.tv',
                  'click.e.twitch.tv', 'email.spotify.com'];
d                const isTrustedRedirect = trustedRedirects.some(t => actualDomain.includes(t));

                if (!isGoogleTrackingUrl && !isTrustedRedirect && displayLooksLikeDomain) {
                  // Check if domains actually differ in a meaningful way
                  // Match if: exact match, OR actual contains display, OR share same base domain
                  const baseDomainMatch = displayDomain.split('.').slice(-2).join('.') ===
                    actualDomain.split('.').slice(-2).join('.');

                  if (displayDomain !== actualDomain &&
                    !actualDomain.includes(displayDomain) &&
                    !displayDomain.includes(actualDomain) &&
                    !baseDomainMatch) {
                    textUrlMismatch = true;
                  }
                }
              } catch (e) { /* Invalid URL, skip */ }
            }

            linkDetails.push({
              url: actualUrl,
              displayText: displayText.substring(0, 100),
              textUrlMismatch
            });
          }
        });
        break;
      }
    }

    // Run client-side phishing analysis
    const clientAnalysis = calculateClientSideThreatScore({
      sender_email: senderEmail,
      subject,
      links: linkDetails.map(l => l.url),
      has_dangerous_attachments: hasDangerousAttachment,
      headers
    });

    if (!senderEmail) {
      log.warn('Could not extract sender email');
      return null;
    }

    return {
      sender_email: senderEmail,
      sender_name: senderName,
      subject,
      links: [...links],
      link_details: linkDetails,
      text_url_mismatches: linkDetails.filter(l => l.textUrlMismatch).length,
      attachment_hashes: attachments.map(a => a.name),
      attachments: attachments,
      has_dangerous_attachments: hasDangerousAttachment,
      headers,
      reply_to_email: replyToEmail,
      reply_to_mismatch: replyToMismatch,
      body_text: bodyText.substring(0, 2000), // Limit for API
      body_text_full_length: bodyText.length,
      client_analysis: clientAnalysis,
      user_email: null,
      extracted_at: Date.now()
    };
  } catch (e) {
    log.error('Error extracting metadata', e);
    return null;
  }
}

async function scanEmailMetadata(metadata, timeout = 30000) {
  const response = await runtimeSendMessage({ type: MSG.scanEmailMetadata, metadata, timeout });
  if (!response) throw new Error('No response');
  if (response.error) throw new Error(response.error);
  return response.data || response;
}

function updateScanButtonState(scanning, text) {
  const btn = document.getElementById(ID.scanBtn);
  if (btn) {
    btn.disabled = scanning;
    btn.textContent = text || (scanning ? '⏳ Scanning...' : 'Scan Email');
  }
  const floatBtn = document.getElementById(ID.floatingScanBtn);
  if (floatBtn) { // Shadow DOM access needed if we want to update the one inside card
    // We will handle re-render or let it be. simpler to just re-render.
  }
}

// ... [getBadgeStyles same, adding specific styles for scan button in card] ...
function getBadgeStyles() {
  return `
    :host { 
      /* Core Colors - Matching Main Extension */
      --primary: #00bcd4; /* Cyan - matching main extension */
      --primary-hover: #00acc1;
      --primary-dark: #0097a7;
      --success: #28a745;
      --warning: #ffc107;
      --danger: #dc3545;
      
      /* Background Colors - Dark Theme */
      --dark: hsl(220, 25%, 3%);
      --panel: hsl(220, 25%, 5%);
      --panel2: hsl(220, 25%, 7%);
      --panel-border: hsl(220, 25%, 15%);
      
      /* Text Colors */
      --text-main: #ffffff;
      --text-secondary: #b0b8c1;
      --text-muted: #9aa0a6;
      
      /* Font */
      --font-stack: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .gr-gmail-2025-float-overlay { 
      position: fixed; 
      top: 0; 
      left: 0; 
      width: 100vw; 
      height: 100vh; 
      background-color: rgba(0, 0, 0, 0.4); 
      z-index: 9998; 
      display: flex; 
      justify-content: center; 
      align-items: center; 
      backdrop-filter: blur(5px); 
      opacity: 0;
      animation: fadeIn 0.2s forwards;
    }
    @keyframes fadeIn { to { opacity: 1; } }

    .gr-gmail-2025-float-card { 
      position: relative; 
      width: 440px; 
      max-width: 90vw;
      max-height: 85vh; 
      background: #0d1117; /* Dark background - hardcoded fallback */
      background: var(--panel, #0d1117); 
      border: 1px solid #21262d;
      border: 1px solid var(--panel-border, #21262d);
      border-radius: 16px; 
      box-shadow: 
        0 20px 25px -5px rgba(0, 0, 0, 0.5), 
        0 8px 10px -6px rgba(0, 0, 0, 0.5),
        0 0 0 1px rgba(255,255,255,0.05);
      display: flex; 
      flex-direction: column; 
      overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-family: var(--font-stack, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif); 
      z-index: 9999; 
      transform: scale(0.95);
      animation: popIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      color: #ffffff;
      color: var(--text-main, #ffffff); 
    }
    @keyframes popIn { to { transform: scale(1); } }

    /* Glassy Header */
    .gr-gmail-2025-float-header { 
      padding: 20px 24px; 
      display: flex; 
      align-items: center; 
      gap: 16px; 
      background: linear-gradient(to bottom, rgba(0, 188, 212, 0.15), transparent);
      border-bottom: 1px solid #21262d;
      border-bottom: 1px solid var(--panel-border, #21262d);
    }
    .gr-gmail-2025-float-header-icon { 
      font-size: 32px; 
      filter: drop-shadow(0 4px 6px rgba(0,0,0,0.2));
    }
    .gr-gmail-2025-float-header-content {
      flex-grow: 1;
    }
    .gr-gmail-2025-float-header-title { 
      font-size: 18px; 
      font-weight: 700; 
      color: #ffffff;
      color: var(--text-main, #ffffff); 
      letter-spacing: -0.025em;
      margin-bottom: 4px;
    }
    .gr-gmail-2025-float-header-subtitle {
       font-size: 13px; 
       color: #9aa0a6;
       color: var(--text-muted, #9aa0a6); 
       font-weight: 400;
    }

    .gr-gmail-2025-float-close-btn { 
      width: 32px;
      height: 32px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: transparent; 
      border: 1px solid transparent; 
      border-radius: 8px;
      font-size: 24px; 
      color: #9aa0a6;
      color: var(--text-muted, #9aa0a6); 
      cursor: pointer; 
      transition: all 0.2s ease;
    }
    .gr-gmail-2025-float-close-btn:hover {
      background: rgba(255, 255, 255, 0.1);
      color: #ffffff;
      color: var(--text-main, #ffffff);
    }

    .gr-gmail-2025-float-body { 
      padding: 0; 
      overflow-y: auto; 
    }

    /* Modern List Items */
    .gr-gmail-2025-float-section { 
      padding: 20px 24px; 
      border-bottom: 1px solid #21262d;
      border-bottom: 1px solid var(--panel-border, #21262d); 
    }
    .gr-gmail-2025-float-section:last-child { border-bottom: none; }

    .gr-gmail-2025-reasons { 
      list-style: none; 
      padding: 0; 
      margin: 0; 
    }
    .gr-gmail-2025-reason-item { 
      display: flex; 
      align-items: flex-start; /* Changed from center to support multiline */
      gap: 12px; 
      font-size: 14px; 
      color: #b0b8c1;
      color: var(--text-muted, #b0b8c1); 
      margin-bottom: 12px; 
      line-height: 1.5;
    }
    .gr-gmail-2025-reason-item:last-child { margin-bottom: 0; }
    
    .gr-gmail-2025-reason-icon {
      flex-shrink: 0;
      width: 20px;
      text-align: center;
      font-weight: bold;
    }
    .gr-gmail-2025-reason-icon.pass { color: #28a745; }
    .gr-gmail-2025-reason-icon.warn { color: #ffc107; }
    .gr-gmail-2025-reason-icon.fail { color: #dc3545; }
    .gr-gmail-2025-reason-icon.neutral { color: #9aa0a6; }

    /* Action Grid */
    .gr-gmail-2025-actions-row { 
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 12px; 
      margin-top: 20px; 
    }
    .gr-gmail-2025-action { 
      padding: 10px; 
      font-size: 12px; 
      border: 1px solid #21262d;
      border: 1px solid var(--panel-border, #21262d); 
      background: #161b22;
      background: var(--panel2, #161b22); 
      color: #b0b8c1;
      color: var(--text-secondary, #b0b8c1); 
      border-radius: 8px; 
      cursor: pointer; 
      font-weight: 600;
      transition: all 0.2s ease;
      text-align: center;
    }
    .gr-gmail-2025-action:hover { 
      background: #0d1117;
      background: var(--panel, #0d1117);
      border-color: #00bcd4;
      border-color: var(--primary, #00bcd4);
      color: #ffffff;
      color: var(--text-main, #ffffff);
      transform: translateY(-1px);
    }

    /* Stats Grid */
    .gr-gmail-2025-float-section-title { 
      font-size: 11px; 
      font-weight: 700; 
      color: #9aa0a6;
      color: var(--text-muted, #9aa0a6); 
      text-transform: uppercase; 
      margin-bottom: 16px; 
      letter-spacing: 0.1em; 
    }
    .gr-gmail-2025-float-stats { 
      display: grid; 
      grid-template-columns: repeat(4, 1fr); 
      gap: 12px; 
    }
    .gr-gmail-2025-float-stat-card { 
      background: #161b22;
      background: var(--panel2, #161b22); 
      padding: 12px 8px; 
      border-radius: 12px; 
      text-align: center; 
      border: 1px solid #21262d;
      border: 1px solid var(--panel-border, #21262d); 
    }
    .gr-gmail-2025-float-stat-card.good { 
      background: rgba(40, 167, 69, 0.15); 
      border-color: rgba(40, 167, 69, 0.3); 
    }
    .gr-gmail-2025-float-stat-card.good .gr-gmail-2025-float-stat-val { color: #28a745; }
    .gr-gmail-2025-float-stat-card.bad { 
      background: rgba(220, 53, 69, 0.15); 
      border-color: rgba(220, 53, 69, 0.3); 
    }
    .gr-gmail-2025-float-stat-card.bad .gr-gmail-2025-float-stat-val { color: #dc3545; }

    .gr-gmail-2025-float-stat-val { 
      font-size: 18px; 
      font-weight: 700; 
      color: #ffffff;
      color: var(--text-main, #ffffff); 
      margin-top: 4px; 
    }
    .gr-gmail-2025-float-stat-label { 
      font-size: 10px; 
      color: #9aa0a6;
      color: var(--text-muted, #9aa0a6); 
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.05em;
    }

    /* Scrollbar */
    .gr-gmail-2025-float-card::-webkit-scrollbar { width: 6px; }
    .gr-gmail-2025-float-card::-webkit-scrollbar-track { background: transparent; }
    .gr-gmail-2025-float-card::-webkit-scrollbar-thumb { background: var(--panel-border); border-radius: 3px; }
    .gr-gmail-2025-float-card::-webkit-scrollbar-thumb:hover { background: var(--primary); }

    /* Rescan Button */
    .gr-gmail-2025-float-rescan {
      background: var(--primary);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 8px 16px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
    }
    .gr-gmail-2025-float-rescan:hover { background: var(--primary-hover); }
    `;
}

function renderBadgeHTML(scanResult) {
  const level = (scanResult?.threat_level || 'unknown').toLowerCase();
  const summary = scanResult?.summary || '';
  const score = scanResult?.threat_score || 0;

  const reasons = scanResult?.reasons && scanResult.reasons.length
    ? scanResult.reasons
    : ['Sender reputation detected', 'Header safety check passed', 'Content verification complete'];

  const senderRep = scanResult?.details?.sender_reputation || {};
  const repScore = senderRep.reputation_score ?? '—';
  const auth = scanResult?.details?.header_analysis || {};
  const links = scanResult?.details?.link_analysis?.links || scanResult?.links || [];

  const isEncrypted = auth.encrypted || false;
  const isTrustedDomain = senderRep?.is_trusted_domain || HIGH_TRUST_DOMAINS.has(senderRep?.domain);

  // Impute authentication for UI if headers are unknown but domain is trusted
  // Gmail strips raw headers, so for trusted domains we show partial verification
  const authStatusUnknown = auth.spf_status === 'unknown' && auth.dkim_status === 'unknown';
  if (authStatusUnknown && isTrustedDomain) {
    // For trusted domains with no header data, consider partially verified
    auth.is_authenticated = true;
    auth.authentication_score = 60; // Partial score for trusted domain without full auth data
  } else if (authStatusUnknown && repScore >= 70) {
    // High reputation sender but no auth data - don't mark as failed
    auth.authentication_score = 50;
  }

  // IMPORTANT: Use threat_score as the PRIMARY indicator for UI severity
  // This prevents contradictions like "Suspicious Email" with 90 trust score
  let severity = 'safe';
  let icon = '🛡️';
  let title = 'Email is Safe';

  // Score-based determination takes priority over text-based level
  if (score >= 67 || level.includes('danger') || level.includes('malicious')) {
    severity = 'danger';
    icon = '⛔';
    title = 'Dangerous Email';
  } else if (score >= 34 || (level.includes('suspicious') && score > 25)) {
    // Only show suspicious if score is actually in the suspicious range
    severity = 'warning';
    icon = '⚠️';
    title = 'Suspicious Email';
  }
  const isTrustedDomain = senderRep?.is_trusted_domain || HIGH_TRUST_DOMAINS.has(senderRep?.domain);
  const isOffline = !!scanResult?.is_offline_analysis;
  const isVerified = !!isTrustedDomain && !isOffline;
  const verifiedDisplay = isVerified ? '✔' : (isTrustedDomain ? '~' : '-');
  const verifiedTooltip = isVerified
    ? 'Verified: trusted domain + live scan'
    : (isTrustedDomain ? 'Trusted domain, but not verified via live scan (offline/local result)' : 'Not verified');

  const spf = (auth.spf_status || 'unknown').toLowerCase();
  const dkim = (auth.dkim_status || 'unknown').toLowerCase();
  const dmarc = (auth.dmarc_status || 'unknown').toLowerCase();
  const anyFail = spf === 'fail' || dkim === 'fail' || dmarc === 'fail';
  const anyPass = spf === 'pass' || dkim === 'pass' || dmarc === 'pass';
  const allUnknown = spf === 'unknown' && dkim === 'unknown' && dmarc === 'unknown';

  const authDisplay = anyPass
    ? '✔'
    : (anyFail ? '✕' : (allUnknown ? '?' : (auth.authentication_score > 40 ? '~' : '?')));
  const authTooltip = anyPass
    ? 'Auth passed (SPF/DKIM/DMARC)'
    : (anyFail ? 'Auth failed (SPF/DKIM/DMARC)' : (allUnknown ? 'Auth unknown (headers not available)' : 'Auth partial/uncertain'));

  // --- HTML Rendering ---

  const mapReasonToHtml = (r) => {
    // Clean existing symbols from text to avoid double icons (e.g. "✓ Safe" -> "Safe")
    let txt = escapeHTML(r).replace(/^[✓!⚠️✕•]\s*/, '').trim();

    let cls = 'gr-gmail-2025-reason-icon ';
    let icon = '•';

    // Classify based on content of the original string OR the cleaned text
    const lowerR = r.toLowerCase();

    if (lowerR.includes('✓') || lowerR.includes('safe') || lowerR.includes('verified') || lowerR.includes('legitimate') || lowerR.includes('passed')) {
      cls += 'pass';
      icon = '✓';
    } else if (lowerR.includes('⚠️') || lowerR.includes('suspicious') || lowerR.includes('differ') || lowerR.includes('mismatch')) {
      cls += 'warn';
      icon = '!';
    } else if (lowerR.includes('dangerous') || lowerR.includes('malicious') || lowerR.includes('attack') || lowerR.includes('failed')) {
      cls += 'fail';
      icon = '✕';
    } else {
      cls += 'neutral';
    }

    return `
      <li class="gr-gmail-2025-reason-item">
        <span class="${cls}">${icon}</span>
        <span>${txt}</span>
      </li>`;
  };

  const safeReasonsHTML = reasons.slice(0, 4).map(mapReasonToHtml).join('');

  return `
    <div class="gr-gmail-2025-float-card" id="${ID.floatCard}">
      
      <!-- Header -->
      <div class="gr-gmail-2025-float-header">
        <div class="gr-gmail-2025-float-header-icon">${icon}</div>
        <div class="gr-gmail-2025-float-header-content">
          <div class="gr-gmail-2025-float-header-title">${title}</div>
          <div class="gr-gmail-2025-float-header-subtitle">${summary}</div>
        </div>
        <button class="gr-gmail-2025-float-close-btn" id="${ID.badgeCloseBtn}">×</button>
      </div>

      <div class="gr-gmail-2025-float-body" id="${ID.badgeDetails}">
        
        <!-- Reasons & Analysis -->
        <div class="gr-gmail-2025-float-section">
          <ul class="gr-gmail-2025-reasons">
             ${safeReasonsHTML}
          </ul>
        </div>
        
        <!-- Key Stats -->
        <div class="gr-gmail-2025-float-section">
          <div class="gr-gmail-2025-float-section-title">Security Analysis</div>
          <div class="gr-gmail-2025-float-stats">
            
            <div class="gr-gmail-2025-float-stat-card ${repScore > 70 ? 'good' : 'bad'}">
              <div class="gr-gmail-2025-float-stat-label">Trust Score</div>
              <div class="gr-gmail-2025-float-stat-val">${repScore}</div>
            </div>

            <div class="gr-gmail-2025-float-stat-card">
              <div class="gr-gmail-2025-float-stat-label">Links</div>
              <div class="gr-gmail-2025-float-stat-val">${links.length}</div>
            </div>

            <div class="gr-gmail-2025-float-stat-card ${isVerified ? 'good' : ''}">
              <div class="gr-gmail-2025-float-stat-label">Verified</div>
              <div class="gr-gmail-2025-float-stat-val" title="${escapeHTML(verifiedTooltip)}">${verifiedDisplay}</div>
            </div>

            <div class="gr-gmail-2025-float-stat-card ${auth.is_authenticated ? 'good' : (authStatusUnknown && (isTrustedDomain || repScore >= 60) ? '' : (auth.authentication_score > 40 ? '' : 'bad'))}">
              <div class="gr-gmail-2025-float-stat-label">Auth</div>
              <div class="gr-gmail-2025-float-stat-val" title="${escapeHTML(authTooltip)}">${authDisplay}</div>
            </div>

          </div>

          <div class="gr-gmail-2025-actions-row">
             <button class="gr-gmail-2025-action" id="${ID.floatingScanBtn}">RE-SCAN</button>
             <button class="gr-gmail-2025-action" data-do="unsubscribe">UNSUBSCRIBE</button>
             <button class="gr-gmail-2025-action" data-do="report">REPORT</button>
          </div>
        </div>

      </div>
    </div>
  `;
}

function createSafetyBadge(scanResult) {
  let host = document.getElementById(ID.shadowHost);
  let shadow, overlay;

  if (!host) {
    host = document.createElement('div');
    host.id = ID.shadowHost;
    document.body.appendChild(host);
    shadow = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = getBadgeStyles();
    shadow.appendChild(style);
    overlay = document.createElement('div');
    overlay.className = 'gr-gmail-2025-float-overlay';
    overlay.id = ID.floatOverlay;
    shadow.appendChild(overlay);
  } else {
    shadow = host.shadowRoot;
    overlay = shadow.getElementById(ID.floatOverlay);
    shadow.querySelector('style').textContent = getBadgeStyles();
  }

  overlay.innerHTML = renderBadgeHTML(scanResult);

  // Close logic
  const close = () => { if (host) host.remove(); document.removeEventListener('keydown', handleEsc); };
  const handleEsc = (e) => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', handleEsc);
  overlay.querySelector(`#${ID.badgeCloseBtn}`)?.addEventListener('click', close);
  overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

  // Floating Scan Button Click (RE-SCAN)
  const cardScanBtn = overlay.querySelector(`#${ID.floatingScanBtn}`);
  if (cardScanBtn) {
    cardScanBtn.onclick = async () => {
      try {
        // Close the overlay to avoid stacking
        close();
        cardScanBtn.style.opacity = '0.7';
        cardScanBtn.disabled = true;

        try {
          // Close current badge first
          close();

          // Small delay to let UI update
          await new Promise((r) => setTimeout(r, 120));

          await scanCurrentEmail({ force: true, timeoutMs: 20000 });
        } catch (e) {
          console.error('WebShield Gmail: RE-SCAN failed', e);
        }
      } catch (e) {
        console.error('WebShield Gmail: RE-SCAN failed', e);
      }
    };
  }

  // Action Buttons with Enhanced Logic
  overlay.querySelectorAll('.gr-gmail-2025-action[data-do]').forEach(btn => {
    btn.onclick = (e) => {
      const action = btn.getAttribute('data-do');
      let success = false;
      if (action === 'spam') success = clickGmailMenuItem('Report spam');
      else if (action === 'report') {
        const emailId = getCurrentEmailId();
        if (emailId) {
          const url = chrome.runtime.getURL(`report.html?id=${encodeURIComponent(emailId)}`);
          window.open(url, '_blank', 'noopener,noreferrer');
          success = true;
        }
      }
      else if (action === 'unsubscribe') {
        const lnk = findUnsubscribeLink();
        if (lnk) { lnk.click(); success = true; }
      }

      if (success) {
        btn.textContent = 'Done';
        btn.disabled = true;
      } else {
        btn.textContent = 'Failed / Not Found';
        btn.disabled = true;
        setTimeout(() => { btn.textContent = action.toUpperCase(); btn.disabled = false; }, 1600);
      }
    };
  });

  storeLastScanResult(scanResult, 'badge');
}

/**
 * Create and inject the Scan Email button into Gmail's UI
 * This function attempts multiple injection strategies for reliability
 */
function createScanButton() {
  // Early exit if button already exists
  if (document.getElementById(ID.scanBtn)) {
    return;
  }

  // Check if we're inside an email conversation
  const emailId = getCurrentEmailId();
  const hasMessageBody = !!document.querySelector('.a3s');

  if (!emailId || !hasMessageBody) {
    // Not viewing an email, clean up any existing button
    document.getElementById(ID.scanBtn)?.remove();
    document.getElementById(ID.scanBtnWrap)?.remove();
    return;
  }

  // Create the scan button with premium styling
  const scanBtn = document.createElement('button');
  scanBtn.id = ID.scanBtn;
  scanBtn.className = 'webshield-scan-btn';
  scanBtn.innerHTML = '🛡️ Scan Email';
  scanBtn.title = 'Scan this email for phishing and security threats';

  // Premium inline styles for reliability (Gmail can override classes)
  scanBtn.style.cssText = `
    background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
    cursor: pointer;
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    margin-left: 12px;
    box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    vertical-align: middle;
  `;

  // Add hover effect via events (since :hover may not work with inline styles)
  scanBtn.addEventListener('mouseenter', () => {
    scanBtn.style.transform = 'translateY(-1px)';
    scanBtn.style.boxShadow = '0 4px 12px rgba(59, 130, 246, 0.4)';
  });
  scanBtn.addEventListener('mouseleave', () => {
    scanBtn.style.transform = 'translateY(0)';
    scanBtn.style.boxShadow = '0 2px 8px rgba(59, 130, 246, 0.3)';
  });

  // Click handler
  scanBtn.onclick = (e) => {
    e.preventDefault();
    e.stopPropagation();
    scanBtn.innerHTML = '⏳ Scanning...';
    scanBtn.style.opacity = '0.8';
    scanBtn.style.pointerEvents = 'none';
    handleScanClick().finally(() => {
      // Reset button after scan (slight delay to show the badge first)
      setTimeout(() => {
        if (scanBtn) {
          scanBtn.innerHTML = '🛡️ Scan Email';
          scanBtn.style.opacity = '1';
          scanBtn.style.pointerEvents = 'auto';
        }
      }, 500);
    });
  };

  // Create wrapper for clean DOM insertion
  const wrapper = document.createElement('span');
  wrapper.id = ID.scanBtnWrap;
  wrapper.style.cssText = 'display: inline-flex; align-items: center; vertical-align: middle;';
  wrapper.appendChild(scanBtn);

  // Try multiple injection points in order of preference
  const injectionStrategies = [
    // Strategy 1: Next to subject line (most common)
    () => {
      const subject = document.querySelector('h2.hP') || document.querySelector('.hP');
      if (subject?.parentElement) {
        subject.parentElement.appendChild(wrapper);
        return true;
      }
      return false;
    },
    // Strategy 2: In the email header/toolbar area
    () => {
      const toolbar = document.querySelector('.ade') || document.querySelector('.G-tF');
      if (toolbar) {
        toolbar.appendChild(wrapper);
        return true;
      }
      return false;
    },
    // Strategy 3: Near the sender information
    () => {
      const senderArea = document.querySelector('.gE') || document.querySelector('.go');
      if (senderArea?.parentElement) {
        senderArea.parentElement.appendChild(wrapper);
        return true;
      }
      return false;
    },
    // Strategy 4: Near the reply button area
    () => {
      const actionBar = document.querySelector('.aHU');
      if (actionBar) {
        actionBar.insertBefore(wrapper, actionBar.firstChild);
        return true;
      }
      return false;
    },
    // Strategy 5: Thread header area
    () => {
      const threadHeader = document.querySelector('[data-thread-perm-id]');
      if (threadHeader?.parentElement) {
        threadHeader.parentElement.appendChild(wrapper);
        return true;
      }
      return false;
    },
    // Strategy 6: Fixed position floating button (fallback)
    () => {
      // Reset wrapper styles for fixed positioning
      wrapper.style.cssText = 'position: fixed; top: 120px; right: 20px; z-index: 9999;';
      scanBtn.style.boxShadow = '0 4px 16px rgba(0, 0, 0, 0.3)';
      document.body.appendChild(wrapper);
      return true;
    }
  ];

  // Try each strategy until one succeeds
  for (const strategy of injectionStrategies) {
    try {
      if (strategy()) {
        log.info('Scan button injected successfully');
        return;
      }
    } catch (e) {
      log.warn('Injection strategy failed:', e.message);
    }
  }

  log.warn('All injection strategies failed');
}

// ... [rest of file: isExtensionDisabled, scanCurrentEmail, handleScanClick, observers] ...

// Re-write of setupEventDelegation NOT needed if we attach onclick directly above.
// But specific ScanCurrentEmail logic needs to be present.

async function isExtensionDisabled() {
  try { return (await chrome.storage.session.get('disabled')).disabled; } catch (e) { return false; }
}

async function scanCurrentEmail(options = {}) {
  if (await isExtensionDisabled()) return;
  if (isScanning) return;

  const runId = ++activeScanRunId;
  const isForce = !!options.force;
  const timeoutMs = typeof options.timeoutMs === 'number' ? options.timeoutMs : 30000;

  // Rate limiting check
  if (!isForce && !canScan()) {
    return;
  }

  // Guard again inside scan
  const emailId = getCurrentEmailId();
  if (!emailId) return;

  // Check cache first to avoid duplicate scans
  const cacheKey = emailId;
  const cachedResult = scanCache.get(cacheKey);
  if (!isForce && cachedResult && Date.now() - cachedResult.timestamp < CACHE_TTL_MS) {
    createSafetyBadge(cachedResult.result);
    return cachedResult.result;
  }

  // Update rate limit timestamp
  if (!isForce) {
    updateScanTimestamp();
  }

  isScanning = true;
  updateScanButtonState(true, '🔍 Scanning...');

  try {
    const metadata = extractEmailMetadata();
    if (!metadata) {
      if (manualScanInProgress) throw new Error('No email found to scan');
      return;
    }

    metadata.gmail_message_id = emailId;
    metadata.thread_id = emailId;

    // Get client-side analysis (already calculated in extractEmailMetadata)
    const clientAnalysis = metadata.client_analysis || calculateClientSideThreatScore(metadata);

    let result;
    try {
      // Try backend scan
      result = await scanEmailMetadata(metadata, timeoutMs);

      // Merge client-side flags with backend result
      if (clientAnalysis.clientFlags.length > 0) {
        result.client_side_flags = clientAnalysis.clientFlags;
        // If client found serious issues, boost threat score
        if (clientAnalysis.clientScore > 30 && result.threat_score < 50) {
          result.threat_score = Math.max(result.threat_score, Math.floor(clientAnalysis.clientScore * 0.7));
        }
        // Add client flags to reasons if not already present
        result.reasons = result.reasons || [];
        for (const flag of clientAnalysis.clientFlags) {
          if (!result.reasons.includes(flag)) {
            result.reasons.push(flag);
          }
        }
      }

      // Add text/URL mismatch warning (major phishing indicator)
      if (metadata.text_url_mismatches > 0) {
        result.reasons = result.reasons || [];
        result.reasons.unshift(`⚠️ ${metadata.text_url_mismatches} link(s) show different URL than displayed text`);
        result.threat_score = Math.min(100, result.threat_score + (metadata.text_url_mismatches * 15));
      }

      // Add reply-to mismatch warning
      if (metadata.reply_to_mismatch) {
        result.reasons = result.reasons || [];
        result.reasons.unshift('⚠️ Reply-to address differs from sender');
        result.threat_score = Math.min(100, result.threat_score + 20);
      }

      // Ensure details exist and inject client-side metadata that backend might miss
      result.details = result.details || {};
      result.details.header_analysis = result.details.header_analysis || {};

      // Merge client-side link details (e.g., displayed-text vs actual URL mismatch)
      // Backend link analysis returns string URLs; UI can also handle objects.
      result.details.link_analysis = result.details.link_analysis || {};
      const la = result.details.link_analysis;
      la.links = la.links || metadata.links || [];
      la.suspicious_links = Array.isArray(la.suspicious_links) ? la.suspicious_links : [];
      if (Array.isArray(metadata.link_details)) {
        const mismatches = metadata.link_details.filter(l => l && l.textUrlMismatch);
        if (mismatches.length > 0) {
          la.suspicious_links = [...la.suspicious_links, ...mismatches];
        }
      }


    } catch (backendError) {
      const msg = (backendError && (backendError.message || backendError.error)) ? String(backendError.message || backendError.error) : '';
      const isTimeout = /timeout|timed out|aborterror/i.test(msg);

      // If live scan timed out, keep the last cached result instead of flipping to offline/local.
      if (isTimeout) {
        const prev = scanCache.get(cacheKey);
        if (prev && prev.result) {
          const prevResult = prev.result;
          const displayResult = {
            ...prevResult,
            reasons: [`⚠️ Live scan timed out; showing last result`, ...(prevResult.reasons || [])]
          };
          if (activeScanRunId === runId) {
            createSafetyBadge(displayResult);
            storeLastScanResult(displayResult, 'scan');
          }
          return displayResult;
        }
      }

      log.warn('Backend unavailable, using client-side analysis', backendError.message);

      // OFFLINE FALLBACK: Use comprehensive client-side analysis
      const senderAnalysis = analyzeSenderEmail(metadata.sender_email);
      const subjectAnalysis = analyzePhishingKeywords(metadata.subject || '');
      const bodyAnalysis = analyzePhishingKeywords(metadata.body_text || '');

      // Calculate comprehensive offline threat score
      let offlineScore = clientAnalysis.clientScore;
      const offlineReasons = [...clientAnalysis.clientFlags];

      // Add body analysis
      if (bodyAnalysis.total > 3) {
        offlineScore += bodyAnalysis.total * 3;
        offlineReasons.push(`Email body contains ${bodyAnalysis.total} suspicious phrases`);
      }

      // Categorize threats found in body
      for (const [category, count] of Object.entries(bodyAnalysis.categories)) {
        if (count > 0) {
          if (category === 'urgency' && count >= 2) {
            offlineReasons.push('Multiple urgency phrases detected');
            offlineScore += 10;
          }
          if (category === 'fear') {
            offlineReasons.push('Fear-inducing language detected');
            offlineScore += 15;
          }
          if (category === 'verification') {
            offlineReasons.push('Suspicious verification request');
            offlineScore += 15;
          }
          if (category === 'financial') {
            offlineReasons.push('Financial/payment language detected');
            offlineScore += 10;
          }
        }
      }

      // Text/URL mismatch is a MAJOR red flag
      if (metadata.text_url_mismatches > 0) {
        offlineReasons.unshift(`⚠️ ${metadata.text_url_mismatches} link(s) show different URL than displayed text`);
        offlineScore += metadata.text_url_mismatches * 20;
      }

      // Reply-to mismatch
      if (metadata.reply_to_mismatch) {
        offlineReasons.unshift('⚠️ Reply-to address differs from sender');
        offlineScore += 25;
      }

      // Determine threat level
      offlineScore = Math.min(100, offlineScore);
      let threatLevel = 'safe';
      let summary = 'Email appears safe (offline analysis)';

      if (offlineScore >= 67) {
        threatLevel = 'dangerous';
        summary = 'High risk email detected (offline analysis)';
      } else if (offlineScore >= 34) {
        threatLevel = 'suspicious';
        summary = 'Suspicious email detected (offline analysis)';
      }

      // Add positive reasons if safe
      if (offlineReasons.length === 0) {
        offlineReasons.push('✓ No suspicious keywords detected');
        offlineReasons.push('✓ Links appear legitimate');
        offlineReasons.push('✓ No dangerous attachments');
      }

      // Final AUTH check check logic for offline mode
      const isTrusted = senderAnalysis.isTrusted;
      // Ensure headers definition exists if we fell into catch block without full context
      const headers = metadata.headers || { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' };

      let finalAuth = false;
      if (headers.spf === 'pass' || headers.dkim === 'pass') finalAuth = true;
      else if (isTrusted) finalAuth = true; // STRONG ASSUMPTION: If it's a known trusted domain (gmail, google, amazon), and we can't find headers, it's likely fine.

      // Score correction: match backend penalty logic
      // If not trusted and not authenticated, max reputation is low
      let offlineRepScore = senderAnalysis.isTrusted ? 95 : (80 - senderAnalysis.riskScore); // Bumping up base score


      // safe = rep*0.4 + auth*0.3 + link*0.3
      let safeScore = (offlineRepScore * 0.4) + (finalAuth ? 30 : 15) + ((100 - offlineScore) * 0.3);

      // Note: In offline mode, we CAN'T verify SPF/DKIM/DMARC because Gmail's DOM doesn't expose it
      // Only add warnings for actual suspicious content, not just "unknown" auth status

      // Check if there are actual risk factors (not just unknown auth)
      const hasRiskFactors = offlineScore > 20 || senderAnalysis.riskScore > 20;

      // Only penalize if there ARE suspicious signals AND sender is unknown
      if (!isTrusted && hasRiskFactors) {
        safeScore = Math.min(safeScore, 55);
        // Only add warning if we haven't already added similar warnings
        if (!offlineReasons.some(r => r.includes('sender') || r.includes('Sender'))) {
          if (senderAnalysis.reasons.length > 0) {
            offlineReasons.unshift(`⚠️ ${senderAnalysis.reasons[0]}`);
          }
        }
      }

      // For unknown senders WITHOUT risk factors, add neutral info (not scary warning)
      if (!isTrusted && !hasRiskFactors && offlineReasons.length === 0) {
        offlineReasons.push('Sender not in known trusted list');
        offlineReasons.push('✓ No suspicious content detected');
        offlineReasons.push('✓ Links appear safe');
      }

      let finalThreatScore = Math.max(0, Math.min(100, 100 - safeScore));

      // Recalculate level based on strict score
      if (finalThreatScore <= 33) threatLevel = 'safe';
      else if (finalThreatScore <= 66) threatLevel = 'suspicious';
      else threatLevel = 'dangerous';

      // Update summary based on final level
      if (threatLevel === 'safe') {
        summary = 'Email appears safe (local analysis)';
      } else if (threatLevel === 'suspicious') {
        summary = 'Email requires caution (local analysis)';
      } else {
        summary = 'Potentially dangerous email detected';
      }

      result = {
        threat_score: Math.round(finalThreatScore),
        threat_level: threatLevel,
        summary: summary,
        reasons: offlineReasons,
        is_offline_analysis: true,
        details: {
          sender_reputation: {
            reputation_score: Math.round(offlineRepScore),
            is_trusted_domain: !!senderAnalysis.isTrusted,
            domain: senderAnalysis.domain || 'unknown'
          },
          header_analysis: {
            spf_status: (headers.spf || 'unknown'),
            dkim_status: (headers.dkim || 'unknown'),
            dmarc_status: (headers.dmarc || 'unknown'),
            spf_posture: 'unknown',
            dkim_posture: 'unknown',
            dmarc_posture: 'unknown',
            is_authenticated: (headers.spf === 'pass' || headers.dkim === 'pass' || headers.dmarc === 'pass'),
            authentication_score: (headers.spf === 'pass' || headers.dkim === 'pass' || headers.dmarc === 'pass')
              ? 80
              : (isTrusted ? 60 : 0)
          },
          link_analysis: {
            links: metadata.links || [],
            link_count: metadata.links?.length || 0,
            suspicious_links: metadata.link_details?.filter(l => l.textUrlMismatch) || []
          },
          content_analysis: {
            phishing_keywords_found: bodyAnalysis.total,
            categories: bodyAnalysis.categories,
            detected_keywords: bodyAnalysis.keywords.slice(0, 10)
          }
        }
      };
    }

    // Ensure reasons exist
    if (!result.reasons || result.reasons.length === 0) {
      result.reasons = ['✓ Sender verified', '✓ Links checked', '✓ Content analyzed'];
    }

    // Update threat level based on final score
    if (result.threat_score >= 67) {
      result.threat_level = 'dangerous';
    } else if (result.threat_score >= 34) {
      result.threat_level = 'suspicious';
    } else {
      result.threat_level = 'safe';
    }

    // Only allow the latest scan invocation to update UI/cache
    if (activeScanRunId !== runId) {
      return result;
    }

    // Cache the result
    scanCache.set(cacheKey, { result, timestamp: Date.now() });

    // Clean old cache entries
    if (scanCache.size > MAX_CACHE_SIZE) {
      const oldestKey = scanCache.keys().next().value;
      scanCache.delete(oldestKey);
    }

    createSafetyBadge(result);
    storeLastScanResult(result, 'scan');

    return result;
  } catch (e) {
    console.error('WebShield Gmail: Scan error', e);

    let errorMessage = 'Scan failed';
    let errorDetails = e?.message || 'Unknown error';

    if (errorDetails.includes('404') || errorDetails.includes('Not Found')) {
      errorMessage = 'Backend Not Configured';
      errorDetails = 'Email scanning endpoint not available. Please ensure the backend server is running with email routes enabled.';
    } else if (errorDetails.includes('Failed to fetch') || errorDetails.includes('NetworkError')) {
      errorMessage = 'Connection Failed';
      errorDetails = 'Cannot connect to backend server. Please check if the server is running.';
    } else if (errorDetails.includes('timeout') || errorDetails.includes('timed out')) {
      errorMessage = 'Request Timeout';
      errorDetails = 'The scan request took too long. Please try again.';
    }

    const errorResult = {
      threat_score: 0,
      threat_level: 'unknown',
      summary: errorMessage,
      reasons: [errorDetails, 'Please check extension settings', 'Contact administrator if issue persists'],
      details: {
        sender_reputation: { reputation_score: 0, is_trusted_domain: false },
        header_analysis: { spf_status: 'unknown', dkim_status: 'unknown', dmarc_status: 'unknown', is_authenticated: false },
        link_analysis: { links: [], link_count: 0 }
      }
    };

    if (manualScanInProgress) {
      createSafetyBadge(errorResult);
    }
  } finally {
    if (activeScanRunId === runId) {
      isScanning = false;
      updateScanButtonState(false);
    } else {
      isScanning = false;
      updateScanButtonState(false);
    }
  }
}

function clearOldScanReports(maxAgeMs) {
  const cutoff = Date.now() - maxAgeMs;
  chrome.storage.local.get(null, (items) => {
    if (chrome.runtime.lastError) return;
    const keysToRemove = [];
    for (const [key, value] of Object.entries(items)) {
      if (key.startsWith('gmail_report_')) {
        // value.timestamp is set in storeLastScanResult
        if (value && value.timestamp && value.timestamp < cutoff) {
          keysToRemove.push(key);
        }
      }
    }
    if (keysToRemove.length > 0) {
      chrome.storage.local.remove(keysToRemove, () => {
        if (!chrome.runtime.lastError) {
          // Silent success
        }
      });
    }
  });
}

async function handleScanClick() {
  await scanCurrentEmail();
}

/**
 * Initialize the Gmail scanner with multiple detection mechanisms
 * Gmail is a Single-Page Application, so we need various hooks
 */
function initGmailScanner() {
  log.info('Initializing Gmail Scanner...');

  const check = setInterval(async () => {
    if (await isExtensionDisabled()) return;
    if (document.querySelector('div[role="main"]')) {
      clearInterval(check);
      log.info('Gmail main content detected, starting observers');

      // Start all observation mechanisms
      observeGmailChanges();
      observeURLChanges();
      startPeriodicCheck();

      // Initial button check
      createScanButton();

      // Clean up old scans on init (24 hour retention)
      clearOldScanReports(24 * 60 * 60 * 1000);
    }
  }, 500); // Check more frequently for faster init
}

/**
 * Watch for Gmail URL/hash changes (SPA navigation)
 */
function observeURLChanges() {
  let lastURL = window.location.href;
  let lastHash = window.location.hash;

  // Listen for hash changes (Gmail uses hash-based routing)
  window.addEventListener('hashchange', () => {
    log.info('Hash changed:', window.location.hash);
    handleNavigationChange();
  });

  // Listen for popstate (browser back/forward)
  window.addEventListener('popstate', () => {
    log.info('Popstate detected');
    handleNavigationChange();
  });

  // Also use History API interception for pushState/replaceState
  const originalPushState = history.pushState;
  const originalReplaceState = history.replaceState;

  history.pushState = function (...args) {
    originalPushState.apply(this, args);
    log.info('pushState detected');
    setTimeout(handleNavigationChange, 100);
  };

  history.replaceState = function (...args) {
    originalReplaceState.apply(this, args);
    setTimeout(handleNavigationChange, 100);
  };
}

/**
 * Handle navigation changes in Gmail
 */
function handleNavigationChange() {
  // Remove old button when navigating
  document.getElementById(ID.scanBtn)?.remove();
  document.getElementById(ID.scanBtnWrap)?.remove();

  // Remove stale badge
  document.getElementById(ID.shadowHost)?.remove();

  // Wait for Gmail to render the new content, then try to add button
  // Gmail can be slow, so we try multiple times
  const attempts = [100, 300, 600, 1000, 1500, 2000];
  attempts.forEach(delay => {
    setTimeout(() => {
      createScanButton();
    }, delay);
  });
}

/**
 * Periodic check for button existence (fallback mechanism)
 * Runs every 2 seconds to ensure button is present when viewing an email
 */
function startPeriodicCheck() {
  setInterval(() => {
    const emailId = getCurrentEmailId();
    const hasMessageBody = !!document.querySelector('.a3s');
    const buttonExists = !!document.getElementById(ID.scanBtn);

    // If we're in an email view but button doesn't exist, try to create it
    if (emailId && hasMessageBody && !buttonExists) {
      log.info('Periodic check: Button missing, recreating...');
      createScanButton();
    }

    // If we're NOT in an email view but button exists, remove it
    if (!emailId && buttonExists) {
      document.getElementById(ID.scanBtn)?.remove();
      document.getElementById(ID.scanBtnWrap)?.remove();
    }
  }, 2000);
}

/**
 * Observe Gmail DOM changes using MutationObserver
 */
function observeGmailChanges() {
  let lastThreadId = getCurrentEmailId();
  let buttonCheckScheduled = false;

  // Debounced callback to reduce CPU usage
  const handleMutation = debounce((mutations) => {
    const currentThreadId = getCurrentEmailId();

    // Handle Thread Change / Navigation
    if (currentThreadId !== lastThreadId) {
      log.info('Thread changed:', lastThreadId, '->', currentThreadId);
      lastThreadId = currentThreadId;

      // Remove stale elements
      document.getElementById(ID.shadowHost)?.remove();
      document.getElementById(ID.scanBtn)?.remove();
      document.getElementById(ID.scanBtnWrap)?.remove();

      // Schedule button creation with multiple attempts
      if (currentThreadId) {
        setTimeout(createScanButton, 200);
        setTimeout(createScanButton, 500);
        setTimeout(createScanButton, 1000);
      }
    }

    // Also check if button needs to be created (regardless of thread change)
    // This handles cases where Gmail re-renders the email view
    if (!buttonCheckScheduled) {
      buttonCheckScheduled = true;
      setTimeout(() => {
        const emailId = getCurrentEmailId();
        const hasMessageBody = !!document.querySelector('.a3s');
        const buttonExists = !!document.getElementById(ID.scanBtn);

        if (emailId && hasMessageBody && !buttonExists) {
          createScanButton();
        }
        buttonCheckScheduled = false;
      }, 300);
    }
  }, 150); // Faster debounce for better responsiveness

  const observer = new MutationObserver(handleMutation);

  // Observe multiple areas of Gmail for better detection
  const observeTargets = [
    document.querySelector('div[role="main"]'),
    document.querySelector('.nH'),
    document.querySelector('.AO'),
    document.body
  ].filter(Boolean);

  observeTargets.forEach(target => {
    observer.observe(target, {
      childList: true,
      subtree: true,
      attributes: false, // Don't need attribute changes
      characterData: false // Don't need text changes
    });
  });

  log.info('MutationObserver started on', observeTargets.length, 'targets');
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const action = message?.type || message?.action;
  if (action === MSG.scanEmailManual) {
    manualScanInProgress = true;
    scanCurrentEmail().then(res => sendResponse({ success: !!res, data: res }))
      .catch(err => sendResponse({ success: false, error: err.message }))
      .finally(() => manualScanInProgress = false);
    return true;
  } else if (action === MSG.safetyAction) {
    // Handle action from popup
    let s = false;
    if (message.action === 'spam') s = clickGmailMenuItem('Report spam');
    else if (message.action === 'report') s = clickGmailMenuItem('Report phishing');
    else if (message.action === 'unsubscribe') {
      const l = findUnsubscribeLink();
      if (l) { l.click(); s = true; }
    }
    sendResponse({ success: s });
    return true;
  } else if (action === 'GMAIL_EXT_SCROLL_TO_REPORT') {
    const host = document.getElementById(ID.shadowHost);
    const card = host?.shadowRoot?.getElementById(ID.floatCard);

    if (card) {
      // Check if in view
      const rect = card.getBoundingClientRect();
      const isInView = (rect.top >= 0 && rect.bottom <= window.innerHeight);
      if (isInView) {
        // Flash border
        const originalBorder = card.style.border;
        card.style.border = '2px solid #1a73e8';
        setTimeout(() => card.style.border = originalBorder, 400);
      } else {
        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    } else {
      // If no card exists, trigger scan to show it
      scanCurrentEmail().then((res) => {
        // After render, try to find and scroll
        setTimeout(() => {
          const newHost = document.getElementById(ID.shadowHost);
          const newCard = newHost?.shadowRoot?.getElementById(ID.floatCard);
          newCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }, 600);
      });
    }
    return true;
  }
});

if (window.location.host === 'mail.google.com') initGmailScanner();
