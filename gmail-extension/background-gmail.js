

// WebShield Gmail Extension Background Script
// Version 2.1.0 - Production Build

// ===== PRODUCTION CONFIGURATION =====
const DEBUG_MODE = true; // TEMPORARILY enabled for OAuth debugging

// Controlled logging - only logs in debug mode
const log = {
  info: (...args) => DEBUG_MODE && console.log('[WebShield BG]', ...args),
  warn: (...args) => DEBUG_MODE && console.warn('[WebShield BG]', ...args),
  error: (...args) => DEBUG_MODE && console.error('[WebShield BG]', ...args)
};

// Import storage utilities (shared)

try {
  importScripts('crypto-storage.js');
} catch (_) {
  // ignore
}

// ===== ONE-TIME MIGRATION: Clear stale OAuth tokens on extension update =====
// Chrome's getAuthToken caches tokens internally even after code changes.
// When scopes change in manifest.json, old tokens lack the new scopes.
// This listener clears everything on install/update so fresh tokens are obtained.
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install' || details.reason === 'update') {
    console.log('[WebShield BG] Extension', details.reason, '- clearing stale OAuth tokens to pick up new scopes');

    // 1. Clear token from chrome.storage.local
    try {
      await chrome.storage.local.remove(['gmail_api_token', 'gmail_api_token_expiry']);
    } catch (_) { /* ignore */ }

    // 2. Clear token from CryptoStorage
    try {
      if (globalThis.CryptoStorage && CryptoStorage.removeEncrypted) {
        await CryptoStorage.removeEncrypted('gmail_api_token');
      }
    } catch (_) { /* ignore */ }

    // 3. Clear Chrome's internal identity token cache
    try {
      const token = await new Promise((resolve) => {
        chrome.identity.getAuthToken({ interactive: false }, (t) => {
          if (chrome.runtime.lastError) resolve(null);
          else resolve(t);
        });
      });
      if (token) {
        await new Promise((resolve) => {
          chrome.identity.removeCachedAuthToken({ token }, () => resolve());
        });
        console.log('[WebShield BG] Cleared Chrome identity cached token');
      }
    } catch (_) { /* ignore */ }

    console.log('[WebShield BG] Stale token cleanup complete. Next auth will request gmail.readonly scope.');
  }
});

function isAllowedLocalEndpoint(endpoint) {
  if (!endpoint || typeof endpoint !== 'string') return false;
  let u;
  try {
    u = new URL(endpoint);
  } catch (_) {
    return false;
  }
  if (u.protocol !== 'http:') return false;
  return u.hostname === 'localhost' || u.hostname === '127.0.0.1';
}

async function verifyOAuthTokenWithBackend(accessToken) {
  if (!accessToken || typeof accessToken !== 'string') {
    return { success: false, error: 'Missing token' };
  }

  try {
    if (!currentAPIBase) {
      await testEndpoints(true);
    }
    const apiBase = currentAPIBase || (await getAPIBaseURL());
    if (!apiBase || !isAllowedLocalEndpoint(apiBase)) {
      return { success: false, error: 'Backend not available' };
    }

    let expectedEmail = null;
    try {
      const ui = await fetch('https://www.googleapis.com/oauth2/v2/userinfo?alt=json', {
        headers: { Authorization: `Bearer ${accessToken}` }
      });
      if (ui.ok) {
        const u = await ui.json().catch(() => null);
        expectedEmail = u && u.email ? String(u.email) : null;
      }
    } catch (_) {
      expectedEmail = null;
    }

    const resp = await fetch(`${apiBase}/api/email/verify-oauth-token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_token: accessToken, expected_email: expectedEmail })
    });

    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      return { success: false, error: data?.detail || `HTTP ${resp.status}` };
    }

    if (data && data.valid) {
      return { success: true, email: data.email || expectedEmail || null };
    }
    return { success: false, error: data?.error || 'Token invalid' };
  } catch (e) {
    return { success: false, error: e?.message || 'Token verification failed' };
  }
}

async function getUserSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({
      notifications: true,
      scan_timeout: 30,
      api_base_override: null
    }, (res) => {
      if (chrome.runtime.lastError) {
        log.error('WebShield Gmail: chrome.storage.sync.get(settings) failed', chrome.runtime.lastError);
      }
      resolve(res || {});
    });
  });
}


// ===== Backend endpoint discovery (copied/minimized from main extension) =====
async function getAPIBaseURL() {
  try {
    const result = await new Promise((resolve) => {
      chrome.storage.sync.get({ api_base_override: null }, (res) => {
        if (chrome.runtime.lastError) {
          log.error('WebShield Gmail: chrome.storage.sync.get failed', chrome.runtime.lastError);
        }
        resolve(res);
      });
    });
    const override = result && result.api_base_override;
    if (override && typeof override === 'string' && override.startsWith('http')) {
      const cleaned = override.replace(/\/$/, '');
      if (isAllowedLocalEndpoint(cleaned)) return cleaned;
      log.warn('WebShield Gmail: rejected non-local api_base_override (local demo mode)', cleaned);
    }
  } catch (_) {
    // ignore
  }
  return 'http://localhost:8000';
}

const FALLBACK_ENDPOINTS = [
  'http://localhost:8000',
  'http://127.0.0.1:8000',
  'http://chrome://extensions/'
];

let currentAPIBase = null;
let isOfflineMode = false;
let endpointTestingInProgress = false;
let endpointTestingPromise = null;

async function testSingleEndpoint(endpoint) {
  // Guard: only allow localhost/127.0.0.1 HTTP endpoints
  if (!isAllowedLocalEndpoint(endpoint)) {
    return { success: false, error: 'Not a valid local endpoint' };
  }
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(`${endpoint}/health`, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'Accept': 'application/json', 'Cache-Control': 'no-cache' }
    });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json().catch(() => ({}));
      if (data.status === 'healthy' || data.message) {
        return { success: true };
      }
    }

    return { success: false };
  } catch (e) {
    return { success: false, error: e?.message };
  }
}

async function setActiveEndpoint(endpoint) {
  currentAPIBase = endpoint;
  isOfflineMode = false;
  chrome.storage.sync.set({
    detectedApiBase: endpoint,
    lastEndpointTest: Date.now(),
    offlineMode: false
  }, () => {
    if (chrome.runtime.lastError) {
      log.error('WebShield Gmail: chrome.storage.sync.set failed', chrome.runtime.lastError);
    }
  });
  return endpoint;
}

async function testEndpoints(forceRetest = false) {
  if (endpointTestingInProgress && !forceRetest) return endpointTestingPromise;
  endpointTestingInProgress = true;

  endpointTestingPromise = (async () => {
    try {
      const dynamicEndpoint = await getAPIBaseURL();
      const first = await testSingleEndpoint(dynamicEndpoint);
      if (first.success) return await setActiveEndpoint(dynamicEndpoint);

      for (const endpoint of FALLBACK_ENDPOINTS) {
        const r = await testSingleEndpoint(endpoint);
        if (r.success) return await setActiveEndpoint(endpoint);
      }

      currentAPIBase = null;
      isOfflineMode = true;
      chrome.storage.sync.set({
        detectedApiBase: null,
        lastEndpointTest: Date.now(),
        offlineMode: true
      }, () => {
        if (chrome.runtime.lastError) {
          log.error('WebShield Gmail: chrome.storage.sync.set failed', chrome.runtime.lastError);
        }
      });
      return null;
    } finally {
      endpointTestingInProgress = false;
    }
  })();

  return endpointTestingPromise;
}

// Start initial endpoint test
testEndpoints().catch(() => {
  // keep silent; popup will show offline state
});

// ===== Gmail scan proxy (avoids CORS issues inside Gmail pages) =====
// Pending-request deduplication map: prevents duplicate API calls for the same email
const _pendingScans = new Map();

async function scanEmailMetadataBackground(metadata, timeout = 30000) {
  if (!metadata || typeof metadata !== 'object') {
    throw new Error('Missing email metadata');
  }

  // Deduplicate: if a scan is already in-flight for this email, reuse it
  const dedupeKey = metadata.gmail_message_id || metadata.sender_email || JSON.stringify(metadata).substring(0, 200);
  if (_pendingScans.has(dedupeKey)) {
    log.info('Reusing in-flight scan for:', dedupeKey);
    return _pendingScans.get(dedupeKey);
  }

  const scanPromise = _doScanEmailMetadata(metadata, timeout);
  _pendingScans.set(dedupeKey, scanPromise);

  try {
    const result = await scanPromise;
    return result;
  } finally {
    _pendingScans.delete(dedupeKey);
  }
}

async function _doScanEmailMetadata(metadata, timeout = 30000) {

  if (!currentAPIBase) {
    // try to discover quickly
    await testEndpoints(true);
  }

  const apiBase = currentAPIBase || (await getAPIBaseURL());
  if (!apiBase) {
    throw new Error('Backend API endpoint not available');
  }

  if (!isAllowedLocalEndpoint(apiBase)) {
    throw new Error('Blocked non-local backend endpoint (local demo mode)');
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const scanType = (metadata && metadata.__scan_type) ? String(metadata.__scan_type) : 'quick';
    const SCAN_URL = `${apiBase}/api/email/scan-metadata`;
    const options = {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'X-Extension-Source': 'gmail-standalone'
      },
      body: JSON.stringify({
        email_metadata: metadata,
        scan_type: scanType
      })
    };

    const res = await fetch(SCAN_URL, options);
    const text = await res.text();

    if (!res.ok) {
      log.error("WebShield Gmail: API non-200", {
        status: res.status,
        body: text
      });

      return {
        error: true,
        status: res.status,
        message: text
      };
    }

    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      log.error("WebShield Gmail: invalid JSON", text);
      return {
        error: true,
        message: "Invalid JSON from backend"
      };
    }

    if (!data || data.error) {
      return data;
    }

    if (data?.threat_score == null) {
      log.error('WebShield Gmail: API invalid response (missing threat_score)', {
        apiBase,
        keys: data && typeof data === 'object' ? Object.keys(data) : null,
        sample: data
      });
      return {
        error: true,
        message: 'Invalid response format'
      };
    }

    return normalizeScanResult(data, metadata);
  } catch (err) {
    log.error("WebShield Gmail: scan failed", {
      name: err?.name,
      message: err?.message,
      stack: err?.stack
    });

    return {
      error: true,
      message: err?.message || "Scan failed"
    };
  } finally {
    clearTimeout(timeoutId);
  }
}

function normalizeScanResult(raw, requestMetadata) {
  const r = (raw && typeof raw === 'object') ? raw : {};
  const threatScore = Number.isFinite(r.threat_score) ? r.threat_score : Number(r.threat_score);
  const score = Number.isFinite(threatScore) ? Math.max(0, Math.min(100, threatScore)) : 0;

  let level = (r.threat_level || '').toString().toLowerCase();
  // Backend uses 'malicious' but UI/CSS uses 'dangerous' — normalize
  if (level === 'malicious') level = 'dangerous';
  if (!level || !['safe', 'suspicious', 'dangerous'].includes(level)) {
    level = score <= 33 ? 'safe' : (score <= 66 ? 'suspicious' : 'dangerous');
  }

  const details = (r.details && typeof r.details === 'object') ? r.details : {};
  const senderRep = (details.sender_reputation && typeof details.sender_reputation === 'object') ? details.sender_reputation : {};
  const headerAnalysis = (details.header_analysis && typeof details.header_analysis === 'object') ? details.header_analysis : {};
  const linkAnalysis = (details.link_analysis && typeof details.link_analysis === 'object') ? details.link_analysis : {};
  const contentAnalysis = (details.content_analysis && typeof details.content_analysis === 'object') ? details.content_analysis : {};

  const reasons = Array.isArray(r.reasons)
    ? r.reasons.map(x => (x == null ? '' : String(x))).filter(Boolean)
    : [];

  // Provide safe defaults so UI never throws
  const normalizedLinkAnalysis = {
    ...linkAnalysis,
    suspicious_links: Array.isArray(linkAnalysis.suspicious_links) ? linkAnalysis.suspicious_links : [],
    links: Array.isArray(linkAnalysis.links)
      ? linkAnalysis.links
      : (Array.isArray(r.links) ? r.links : []),
  };
  normalizedLinkAnalysis.link_count = Number.isFinite(normalizedLinkAnalysis.link_count)
    ? normalizedLinkAnalysis.link_count
    : (Array.isArray(normalizedLinkAnalysis.links) ? normalizedLinkAnalysis.links.length : 0);

  const normalizedContentAnalysis = {
    ...contentAnalysis
  };
  if (normalizedContentAnalysis.phishing_keywords_found == null) {
    normalizedContentAnalysis.phishing_keywords_found = Number.isFinite(contentAnalysis.phishing_keywords_found)
      ? contentAnalysis.phishing_keywords_found
      : 0;
  }

  // Fallback: if backend didn't provide keyword count, use client-side analysis if present
  if (normalizedContentAnalysis.phishing_keywords_found === 0) {
    const client = requestMetadata?.client_analysis;
    if (client && typeof client === 'object') {
      const detected = client?.clientFlags;
      if (Array.isArray(detected) && detected.length) {
        normalizedContentAnalysis.phishing_keywords_found = detected.length;
      }
    }
  }

  // Preserve ALL backend header_analysis fields (gmail_api_verified, authentication_score,
  // spf_posture, dkim_posture, dmarc_posture, etc.) and add safe defaults for core fields
  const normalizedHeaderAnalysis = {
    ...headerAnalysis,
    spf_status: headerAnalysis.spf_status || headerAnalysis.spf || 'unknown',
    dkim_status: headerAnalysis.dkim_status || headerAnalysis.dkim || 'unknown',
    dmarc_status: headerAnalysis.dmarc_status || headerAnalysis.dmarc || 'unknown',
    is_authenticated: !!headerAnalysis.is_authenticated,
    encrypted: !!headerAnalysis.encrypted,
    gmail_api_verified: !!headerAnalysis.gmail_api_verified,
    authentication_score: Number.isFinite(headerAnalysis.authentication_score) ? headerAnalysis.authentication_score : 0
  };

  return {
    ...r,
    threat_score: score,
    threat_level: level,
    summary: (r.summary || 'Analysis complete').toString(),
    reasons,
    // Preserve top-level backend fields (ai_explanation, confidence)
    ai_explanation: r.ai_explanation || null,
    confidence: Number.isFinite(r.confidence) ? r.confidence : null,
    details: {
      ...details,
      sender_reputation: {
        ...senderRep
      },
      header_analysis: normalizedHeaderAnalysis,
      link_analysis: normalizedLinkAnalysis,
      content_analysis: normalizedContentAnalysis
    }
  };
}

// ===== Last scan result storage for popup =====
const LAST_SCAN_KEY = 'webshield_gmail_last_scan';

function storeLastScan(payload) {
  const data = {
    ...payload,
    storedAt: Date.now()
  };
  return new Promise((resolve) => {
    chrome.storage.local.set({ [LAST_SCAN_KEY]: data }, () => {
      if (chrome.runtime.lastError) {
        log.error('WebShield Gmail: chrome.storage.local.set failed', chrome.runtime.lastError);
      }
      resolve(data);
    });
  });
}

function getLastScan() {
  return new Promise((resolve) => {
    chrome.storage.local.get({ [LAST_SCAN_KEY]: null }, (res) => {
      if (chrome.runtime.lastError) {
        log.error('WebShield Gmail: chrome.storage.local.get failed', chrome.runtime.lastError);
      }
      resolve(res[LAST_SCAN_KEY] || null);
    });
  });
}

// ===== Messaging =====
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const type = msg?.type;

  (async () => {
    switch (type) {
      case 'GMAIL_EXT_SCAN_EMAIL_METADATA': {
        try {
          const data = await scanEmailMetadataBackground(msg.metadata, msg.timeout);
          if (data && typeof data === 'object' && data.error) {
            sendResponse({
              success: false,
              error: String(data.message || data.error || 'Scan failed'),
              details: data
            });
            return;
          }
          sendResponse({ success: true, data });
        } catch (e) {
          const err = (e instanceof Error)
            ? { name: e.name, message: e.message, details: e.details || null }
            : { name: 'UnknownError', message: String(e || 'Scan failed'), details: null };
          sendResponse({ success: false, error: err.message, details: err });
        }
        return;
      }

      case 'GMAIL_EXT_DANGEROUS_EMAIL_DETECTED': {
        // Optional: show notification for dangerous emails
        try {
          const settings = await getUserSettings();
          if (settings.notifications) {
            chrome.notifications.create({
              type: 'basic',
              title: '⚠️ Dangerous Email Detected',
              message: `Threat Score: ${msg.data?.threat_score ?? '?'} / 100\n${msg.data?.summary ?? ''}`,
              priority: 2
            }, () => {
              if (chrome.runtime.lastError) {
                log.error('WebShield Gmail: chrome.notifications.create failed', chrome.runtime.lastError);
              }
            });
          }
        } catch (_) {
          // ignore
        }
        sendResponse({ success: true });
        return;
      }

      case 'GMAIL_EXT_UPDATE_BADGE': {
        const { text, color } = msg;
        if (text !== undefined) {
          chrome.action.setBadgeText({ text: String(text) });
        }
        if (color) {
          chrome.action.setBadgeBackgroundColor({ color });
        }
        sendResponse({ success: true });
        return;
      }

      case 'GMAIL_EXT_STORE_LAST_EMAIL_SCAN': {
        const payload = msg.payload || {};
        const timestamp = Date.now();
        const stored = await storeLastScan(payload);

        // Also store the simple timestamp as requested
        chrome.storage.local.set({ gmail_last_scan_ts: timestamp }, () => {
          // ignore errors
        });

        sendResponse({ success: true, data: stored });
        return;
      }

      case 'GMAIL_EXT_GET_LAST_EMAIL_SCAN': {
        const stored = await getLastScan();
        // Get the separate timestamp too if needed, but 'stored' has storedAt.
        // We'll just return what we have.
        sendResponse({ success: true, data: stored });
        return;
      }

      case 'GMAIL_EXT_GET_STATUS': {
        sendResponse({
          apiBase: currentAPIBase,
          offlineMode: isOfflineMode
        });
        return;
      }

      case 'GMAIL_API_AUTH': {
        // Initiate Gmail API OAuth flow using Chrome Identity API
        try {
          let accessToken = null;
          let expiresIn = 3600; // Default 1 hour expiry

          // Preferred: chrome.identity.getAuthToken (uses manifest.json oauth2 config)
          // This automatically uses the scopes from manifest.json and handles consent
          if (chrome.identity && chrome.identity.getAuthToken) {
            try {
              // First try non-interactive (silent) to check for existing token
              const silentResult = await new Promise((resolve, reject) => {
                chrome.identity.getAuthToken({ interactive: false }, (token) => {
                  if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                  } else {
                    resolve(token);
                  }
                });
              }).catch(() => null);

              if (silentResult) {
                // Verify the silent token actually has sufficient scopes
                // by doing a quick HEAD / minimal-cost request to Gmail API
                // MUST test against an endpoint that requires gmail.readonly (like messages.list)
                // /profile only needs gmail.metadata, so it gave false positives
                let scopeOk = false;
                try {
                  const testResp = await fetch(
                    'https://www.googleapis.com/gmail/v1/users/me/messages?maxResults=1',
                    { headers: { 'Authorization': `Bearer ${silentResult}` } }
                  );
                  scopeOk = testResp.ok;
                } catch (_) {
                  scopeOk = false;
                }

                if (scopeOk) {
                  accessToken = silentResult;
                  log.info('Got token silently via getAuthToken (scopes verified)');
                } else {
                  // Token has stale/insufficient scopes — remove it and get fresh one
                  log.info('Silent token has insufficient scopes, clearing and re-requesting...');
                  try {
                    await new Promise((resolve) => {
                      chrome.identity.removeCachedAuthToken({ token: silentResult }, () => resolve());
                    });
                  } catch (_) { /* ignore */ }

                  // Now get a fresh token interactively (will prompt for new scopes)
                  accessToken = await new Promise((resolve, reject) => {
                    chrome.identity.getAuthToken({ interactive: true }, (token) => {
                      if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
                      } else {
                        resolve(token);
                      }
                    });
                  });
                  log.info('Got fresh token with updated scopes via interactive getAuthToken');
                }
              } else {
                // Interactive: prompts user for consent with correct scopes
                accessToken = await new Promise((resolve, reject) => {
                  chrome.identity.getAuthToken({ interactive: true }, (token) => {
                    if (chrome.runtime.lastError) {
                      reject(new Error(chrome.runtime.lastError.message));
                    } else {
                      resolve(token);
                    }
                  });
                });
                log.info('Got token interactively via getAuthToken');
              }
            } catch (getAuthErr) {
              log.warn('getAuthToken failed, falling back to launchWebAuthFlow:', getAuthErr.message);
              accessToken = null;
            }
          }

          // Fallback: launchWebAuthFlow (manual OAuth)
          if (!accessToken) {
            const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
            authUrl.searchParams.set('client_id', '867726207258-ba75ij27f13956hsh2288au1jnploomq.apps.googleusercontent.com');
            authUrl.searchParams.set('response_type', 'token');
            authUrl.searchParams.set('redirect_uri', chrome.identity.getRedirectURL());
            authUrl.searchParams.set('scope', 'https://www.googleapis.com/auth/gmail.metadata https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/userinfo.email');
            authUrl.searchParams.set('prompt', 'consent');

            const redirectUrl = await chrome.identity.launchWebAuthFlow({
              url: authUrl.toString(),
              interactive: true
            });

            const url = new URL(redirectUrl);
            const params = new URLSearchParams(url.hash.substring(1));
            accessToken = params.get('access_token');

            // Get actual expiry from OAuth response (fallback to 3600 if not present/invalid)
            const expiresInParam = params.get('expires_in');
            const oauthExpiresIn = expiresInParam ? parseInt(expiresInParam, 10) : 3600;
            expiresIn = Number.isNaN(oauthExpiresIn) ? 3600 : oauthExpiresIn;
          }

          if (!accessToken) {
            throw new Error('No access token received');
          }

          const verification = await verifyOAuthTokenWithBackend(accessToken);
          if (!verification.success) {
            try {
              await fetch(`https://accounts.google.com/o/oauth2/revoke?token=${accessToken}`);
            } catch (_) {
              // ignore
            }
            throw new Error(verification.error || 'Backend token verification failed');
          }

          const expiryMs = Date.now() + (expiresIn * 1000);
          if (globalThis.CryptoStorage && CryptoStorage.setEncrypted) {
            await CryptoStorage.setEncrypted('gmail_api_token', {
              token: accessToken,
              stored_at: Date.now(),
              expires_at: expiryMs,
              verified: true,
              email: verification.email || null
            });
          } else {
            await new Promise((resolve, reject) => {
              chrome.storage.local.set({
                'gmail_api_token': accessToken,
                'gmail_api_token_expiry': expiryMs
              }, () => {
                if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                else resolve();
              });
            });
          }

          await new Promise((resolve) => {
            chrome.storage.local.set({
              'gmail_api_connected': true,
              'gmail_api_token_verified': true
            }, resolve);
          });

          log.info('Gmail API OAuth successful');
          sendResponse({ success: true, token: accessToken });
        } catch (err) {
          log.error('Gmail API OAuth failed:', err);
          sendResponse({ success: false, error: err.message });
        }
        return;
      }

      case 'GMAIL_API_DISCONNECT': {
        try {
          // Get token to revoke
          const result = await new Promise((resolve) => {
            chrome.storage.local.get(['gmail_api_token'], resolve);
          });

          let tokenToRevoke = result && result.gmail_api_token ? result.gmail_api_token : null;
          if (!tokenToRevoke && globalThis.CryptoStorage && CryptoStorage.getEncrypted) {
            try {
              const enc = await CryptoStorage.getEncrypted('gmail_api_token');
              tokenToRevoke = enc && enc.token ? enc.token : null;
            } catch (_) {
              tokenToRevoke = null;
            }
          }

          if (tokenToRevoke) {
            // Remove from Chrome's internal cache first (for getAuthToken tokens)
            try {
              if (chrome.identity && chrome.identity.removeCachedAuthToken) {
                await new Promise((resolve) => {
                  chrome.identity.removeCachedAuthToken({ token: tokenToRevoke }, () => resolve());
                });
              }
            } catch (_) {
              // ignore
            }

            // Revoke token with Google
            try {
              await fetch(`https://accounts.google.com/o/oauth2/revoke?token=${tokenToRevoke}`);
            } catch (_) {
              // Ignore revoke errors
            }
          }

          // Clear stored data
          if (globalThis.CryptoStorage && CryptoStorage.removeEncrypted) {
            try {
              await CryptoStorage.removeEncrypted('gmail_api_token');
            } catch (_) {
              // ignore
            }
          }

          await new Promise((resolve) => {
            chrome.storage.local.remove([
              'gmail_api_token',
              'gmail_api_token_expiry',
              'gmail_api_connected',
              'gmail_api_token_verified'
            ], resolve);
          });

          log.info('Gmail API disconnected');
          sendResponse({ success: true });
        } catch (err) {
          log.error('Gmail API disconnect failed:', err);
          sendResponse({ success: false, error: err.message });
        }
        return;
      }

      default: {
        sendResponse({ success: false, error: 'Unknown message type', details: { type } });
        return;
      }
    }
  })().catch((err) => {
    const e = (err instanceof Error)
      ? { name: err.name, message: err.message, details: err.details || null }
      : { name: 'UnknownError', message: String(err || 'Unknown error'), details: null };
    sendResponse({ success: false, error: e.message, details: e });
  });

  return true;
});
