/*
Threat-score breakdown (0-100)
- Sender reputation (0-40)
  – Domain age / MX / SPF / DKIM / DMARC weight
- Content checks (0-30)
  – Suspicious keywords, link-to-text ratio, hidden URLs
- Link analysis (0-30)
  – PhishTank, Google Safe Browsing, URL entropy, redirect count
Final score = 100 - (above sum)
≤ 33  → SAFE (green)
34-66 → SUSPICIOUS (amber)
≥ 67  → MALICIOUS (red)
*/

// WebShield Gmail Extension Background Script
// Version 2.0.0 - Production Build

// ===== PRODUCTION CONFIGURATION =====
const DEBUG_MODE = false; // Set to true for development logging

// Controlled logging - only logs in debug mode
const log = {
  info: (...args) => DEBUG_MODE && console.log('[WebShield BG]', ...args),
  warn: (...args) => DEBUG_MODE && console.warn('[WebShield BG]', ...args),
  error: (...args) => DEBUG_MODE && console.error('[WebShield BG]', ...args)
};

// Import storage utilities (shared)


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
      return override.replace(/\/$/, '');
    }
  } catch (_) {
    // ignore
  }
  return 'http://localhost:8000';
}

const FALLBACK_ENDPOINTS = [
  'http://localhost:8000',
  'http://127.0.0.1:8000',
  'https://pggjs0c8-8000.inc1.devtunnels.ms'
];

let currentAPIBase = null;
let isOfflineMode = false;
let endpointTestingInProgress = false;
let endpointTestingPromise = null;

async function testSingleEndpoint(endpoint) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(`${endpoint}/api/health`, {
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
async function scanEmailMetadataBackground(metadata, timeout = 30000) {
  if (!metadata || typeof metadata !== 'object') {
    throw new Error('Missing email metadata');
  }

  if (!currentAPIBase) {
    // try to discover quickly
    await testEndpoints(true);
  }

  const apiBase = currentAPIBase || (await getAPIBaseURL());
  if (!apiBase) {
    throw new Error('Backend API endpoint not available');
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    let res;
    try {
      res = await fetch(`${apiBase}/api/email/scan-metadata`, {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'X-Extension-Source': 'gmail-standalone'
        },
        body: JSON.stringify({
          email_metadata: metadata,
          scan_type: 'full'
        })
      });
    } catch (fetchErr) {
      log.error('WebShield Gmail: fetch failed', {
        apiBase,
        message: fetchErr?.message,
        name: fetchErr?.name,
        stack: fetchErr?.stack
      });
      throw fetchErr;
    }

    clearTimeout(timeoutId);

    if (res.status !== 200) {
      const statusText = res.statusText || `HTTP ${res.status}`;
      let bodyText = '';
      try {
        bodyText = await res.text();
      } catch (_) {
        // ignore
      }
      log.error('WebShield Gmail: API non-200', {
        apiBase,
        status: res.status,
        statusText,
        bodyText
      });
      throw { error: statusText };
    }

    let json;
    try {
      json = await res.json();
    } catch (parseErr) {
      log.error('WebShield Gmail: API JSON parse failed', {
        apiBase,
        message: parseErr?.message,
        stack: parseErr?.stack
      });
      throw { error: 'Invalid response format' };
    }

    if (json?.threat_score == null) {
      log.error('WebShield Gmail: API invalid response (missing threat_score)', {
        apiBase,
        keys: json && typeof json === 'object' ? Object.keys(json) : null,
        sample: json
      });
      throw { error: 'Invalid response format' };
    }

    return json;
  } catch (err) {
    clearTimeout(timeoutId);
    const isTimeout = err?.name === 'AbortError' || /timed out/i.test(err?.message || '');
    if (isTimeout) {
      log.error('WebShield Gmail: request timed out', { apiBase, timeout });
      throw { error: `Request timed out at ${apiBase}` };
    }
    if (err && typeof err === 'object' && 'error' in err) {
      log.error('WebShield Gmail: scan failed (structured)', err);
      throw err;
    }
    log.error('WebShield Gmail: scan failed', err);
    throw { error: err?.message || 'Scan failed (background)' };
  }
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
        const data = await scanEmailMetadataBackground(msg.metadata, msg.timeout);
        sendResponse({ data });
        return;
      }

      case 'GMAIL_EXT_DANGEROUS_EMAIL_DETECTED': {
        // Optional: show notification for dangerous emails
        try {
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

      default:
        sendResponse({ error: 'Unknown message type' });
        return;
    }
  })().catch((err) => {
    if (err && typeof err === 'object' && 'error' in err) {
      sendResponse({ error: err.error });
      return;
    }
    sendResponse({ error: err?.message || 'Unknown error' });
  });

  return true;
});
