// WebShield Content Script
const WEBSHIELD_WHITELIST = [
  "pggjs0c8-8000.inc1.devtunnels.ms",
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  // Add any other trusted domains here
];

// Private/Local IP patterns - never block these
const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,  // 127.x.x.x loopback
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,    // 10.x.x.x private
  /^192\.168\.\d{1,3}\.\d{1,3}$/,       // 192.168.x.x private
  /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/, // 172.16-31.x.x private
  /^0\.0\.0\.0$/,                        // 0.0.0.0
  /^::1$/,                               // IPv6 loopback
  /^\[::1\]$/,                           // IPv6 loopback with brackets
];

// Protocols to skip (system pages)
const SKIP_PROTOCOLS = [
  'chrome://',
  'chrome-extension://',
  'edge://',
  'about:',
  'file://',
  'moz-extension://',
  'devtools://',
];

// Check if hostname is private/local - should never be blocked or scanned
function isPrivateOrLocalhost(hostname) {
  if (!hostname) return true;

  // Check exact whitelist match
  if (WEBSHIELD_WHITELIST.includes(hostname.toLowerCase())) {
    return true;
  }

  // Check private IP patterns
  for (const pattern of PRIVATE_IP_PATTERNS) {
    if (pattern.test(hostname)) {
      return true;
    }
  }

  // Check for localhost with ports (e.g., localhost:3000)
  const hostnameWithoutPort = hostname.split(':')[0];
  if (hostnameWithoutPort === 'localhost' || hostnameWithoutPort === '127.0.0.1') {
    return true;
  }

  return false;
}

// Check if URL should be skipped entirely
function shouldSkipUrl(url) {
  if (!url) return true;

  // Skip system protocols
  for (const protocol of SKIP_PROTOCOLS) {
    if (url.startsWith(protocol)) {
      return true;
    }
  }

  // Skip new tab pages
  if (url === 'about:blank' || url === 'about:newtab' || url.startsWith('chrome://newtab')) {
    return true;
  }

  return false;
}

// Enhanced security configuration
const SECURITY_CONFIG = {
  sslCheckEnabled: true,
  sslBlockInvalid: true,
  sslStrictness: 'moderate',
  threatDetectionEnabled: true,

  autoBlockHighThreat: false,
  showDetailedAlerts: true
};

// Rate limiting for content script
let lastCheckTime = 0;
const MIN_CHECK_INTERVAL = 1500; // 1.5 seconds between checks for quicker reactions

// Safe DOM manipulation function
function safeAppendChild(parent, child) {
  try {
    if (parent && child && parent.appendChild) {
      return parent.appendChild(child);
    }
    return false;
  } catch (error) {
    console.error('WebShield: DOM append error:', error.message);
    return false;
  }
}

// Safe document.body check
function getSafeBody() {
  try {
    return document.body || document.documentElement;
  } catch (error) {
    console.error('WebShield: Cannot access document body:', error.message);
    return null;
  }
}

(function () {
  try {
    const url = window.location.href;

    // Never run website-protection logic inside Gmail. The project has a dedicated Gmail extension.
    try {
      const host = new URL(url).hostname;
      if (host === 'mail.google.com') {
        return;
      }
    } catch (_) {
      // ignore
    }

    // Skip system URLs (chrome://, about:, file://, etc.)
    if (shouldSkipUrl(url)) {
      console.log('WebShield: Skipping system URL:', url);
      return;
    }

    // Check if extension is enabled before running any logic
    chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
      if (!settings.extensionEnabled) {
        // Extension is disabled: update icon and do nothing else
        updateSafeBrowsingIcon('disabled');
        return;
      }

      try {
        const hostname = new URL(url).hostname;

        // Skip private/local hosts (localhost, 127.0.0.1, 192.168.x.x, etc.)
        if (isPrivateOrLocalhost(hostname)) {
          console.log('WebShield: Skipping local/private host:', hostname);
          updateSafeBrowsingIcon('safe'); // Show safe icon for local hosts
          return;
        }

        // Initialize security analysis for external sites only
        initializeSecurityAnalysis();
        // Watch for SPA navigations
        watchUrlChanges();
      } catch (urlError) {
        console.log('WebShield: Invalid URL, skipping:', urlError.message);
      }
    });
  } catch (error) {
    console.error('WebShield: Content script initialization failed:', error.message);
  }
})();

// Enhanced initialization function
function initializeSecurityAnalysis() {
  try {
    const url = window.location.href;

    // Check if we should rate limit this check
    const now = Date.now();
    if (now - lastCheckTime < MIN_CHECK_INTERVAL) {
      console.log('WebShield: Rate limiting content check');
      return;
    }
    lastCheckTime = now;

    // Load settings and perform security analysis
    chrome.storage.sync.get(['ssl_check_enabled', 'ssl_block_invalid', 'ssl_strictness', 'threat_detection_enabled'], (settings) => {
      try {
        const config = {
          sslCheckEnabled: settings.ssl_check_enabled !== false,
          sslBlockInvalid: settings.ssl_block_invalid !== false,
          sslStrictness: settings.ssl_strictness || 'moderate',
          threatDetectionEnabled: settings.threat_detection_enabled !== false
        };

        if (!config.sslCheckEnabled && !config.threatDetectionEnabled) {
          console.log('WebShield: All security checks disabled');
          updateSafeBrowsingIcon('safe');
          return;
        }

        // Perform comprehensive security analysis
        performSecurityAnalysis(url, config);
      } catch (error) {
        console.error('WebShield: Settings processing failed:', error.message);
      }
    });
  } catch (error) {
    console.error('WebShield: Security analysis initialization failed:', error.message);
  }
}

// Enhanced security analysis function
async function performSecurityAnalysis(url, config) {
  try {
    console.log('WebShield: Starting security analysis for:', url);

    // Check for HTTPS first
    if (!url.startsWith('https://')) {
      handleNonHTTPS(url);
      return;
    }

    // Perform parallel security checks
    const checks = [];

    if (config.sslCheckEnabled) {
      checks.push(checkSSLSecurity(url));
    }

    if (config.threatDetectionEnabled) {
      checks.push(checkThreatLevel(url));
    }



    try {
      const results = await Promise.allSettled(checks);
      processSecurityResults(results, url);
    } catch (error) {
      console.error('WebShield: Security analysis failed:', error);
      updateSafeBrowsingIcon('warning');
    }
  } catch (error) {
    console.error('WebShield: Security analysis failed:', error);
    updateSafeBrowsingIcon('warning');
  }
}

// Enhanced SSL security check with error handling
async function checkSSLSecurity(url) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: 'CHECK_SSL_CERTIFICATE', url }, (sslResult) => {
        if (chrome.runtime.lastError) {
          console.warn('WebShield: SSL check connection error:', chrome.runtime.lastError.message);
          resolve({ type: 'ssl', result: { valid: true, offline: true } });
          return;
        }
        console.log('WebShield: SSL check result:', sslResult);
        resolve({ type: 'ssl', result: sslResult });
      });
    } catch (error) {
      console.warn('WebShield: SSL check failed:', error.message);
      resolve({ type: 'ssl', result: { valid: true, offline: true } });
    }
  });
}

// Enhanced threat level check with error handling
async function checkThreatLevel(url) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage({ type: 'CHECK_URL', url }, (threatResult) => {
        if (chrome.runtime.lastError) {
          console.warn('WebShield: Threat check connection error:', chrome.runtime.lastError.message);
          resolve({ type: 'threat', result: { results: { threat_level: 'low', malicious_count: 0, suspicious_count: 0 } } });
          return;
        }
        console.log('WebShield: Threat check result:', threatResult);
        resolve({ type: 'threat', result: threatResult });
      });
    } catch (error) {
      console.warn('WebShield: Threat check failed:', error.message);
      resolve({ type: 'threat', result: { results: { threat_level: 'low', malicious_count: 0, suspicious_count: 0 } } });
    }
  });
}



// Process all security results with new threat level logic
// Rules:
// - HIGH/BLOCK: No SSL OR >2 engines flag malicious/suspicious
// - MODERATE: 1-2 engines flag (warning, no block)
// - SAFE: SSL valid AND 0 engines flag
function processSecurityResults(results, url) {
  let sslValid = true;
  let maliciousCount = 0;
  let suspiciousCount = 0;

  results.forEach((result) => {
    if (result.status === 'fulfilled') {
      const { type, result: data } = result.value;

      switch (type) {
        case 'ssl':
          if (data?.valid === false) {
            sslValid = false;
          } else if (data?.valid) {
            showSSLInfo(data);
          }
          break;

        case 'threat':
          if (data?.results) {
            maliciousCount = data.results.malicious_count || 0;
            suspiciousCount = data.results.suspicious_count || 0;
          }
          break;
      }
    }
  });

  const totalFlags = maliciousCount + suspiciousCount;

  // Apply new threat level rules
  if (!sslValid) {
    // No SSL = High risk, block
    showWarningOverlay('no-https');
    notifyBackground('danger', url);
    updateSafeBrowsingIcon('danger');
  } else if (totalFlags > 2) {
    // More than 2 engines flagged = High risk, block
    showWarningOverlay('block-site');
    notifyBackground('danger', url);
    updateSafeBrowsingIcon('danger');
  } else if (totalFlags >= 1) {
    // 1-2 engines flagged = Moderate risk, warning but no block
    updateSafeBrowsingIcon('warning');
    showRiskIndicator('Moderate Risk ⚠️');
  } else {
    // 0 flags and SSL valid = Safe
    updateSafeBrowsingIcon('safe');
    showRiskIndicator('Safe ✅');
  }
}

// Enhanced non-HTTPS handling
function handleNonHTTPS(url) {
  console.log('WebShield: Non-HTTPS site detected:', url);

  if (document.body) {
    showWarningOverlay('no-https');
    notifyBackground('warning', url);
  } else {
    window.addEventListener('DOMContentLoaded', () => {
      showWarningOverlay('no-https');
      notifyBackground('warning', url);
    });
  }

  updateSafeBrowsingIcon('danger');
}

// Enhanced warning overlay with better styling
function showWarningOverlay(type, sslDetails = null) {
  // Remove existing overlay
  const existingOverlay = document.getElementById('webshield-overlay');
  if (existingOverlay) {
    existingOverlay.remove();
  }

  const overlay = document.createElement('div');
  overlay.id = 'webshield-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(220, 53, 69, 0.95);
    z-index: 999999;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: white;
    text-align: center;
    padding: 20px;
  `;

  let title, message, details;

  switch (type) {
    case 'no-https':
      title = '⚠️ SECURITY WARNING ⚠️';
      message = 'This site is not using HTTPS encryption. Your data may be vulnerable to interception.';
      details = 'Proceed with extreme caution or consider using a different site.';
      break;

    case 'invalid-ssl':
      title = '🔒 SSL CERTIFICATE ISSUE';
      message = 'This site has an invalid or expired SSL certificate.';
      details = sslDetails?.error || 'Certificate validation failed.';
      break;
    case 'block-site':
      title = '🚨 BLOCKED BY WEBSHIELD';
      message = 'This site has been blocked due to a high security risk!';
      details = 'Access to this site is restricted for your safety.';
      break;
    default:
      title = '⚠️ SECURITY ALERT';
      message = 'This site has been flagged as potentially dangerous.';
      details = 'Proceed with caution.';
  }

  overlay.innerHTML = `
    <div style="max-width: 600px; background: rgba(0,0,0,0.8); padding: 30px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
      <h1 style="margin: 0 0 20px 0; font-size: 24px; color: #ff6b6b;">${title}</h1>
      <p style="margin: 0 0 15px 0; font-size: 16px; line-height: 1.5;">${message}</p>
      <p style="margin: 0 0 25px 0; font-size: 14px; color: #ffd93d;">${details}</p>
      <div style="display: flex; gap: 15px; justify-content: center;">
        <button id="webshield-proceed" style="
          background: #dc3545;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 14px;
          font-weight: bold;
        ">Proceed Anyway</button>
        <button id="webshield-go-back" style="
          background: #28a745;
          color: white;
          border: none;
          padding: 12px 24px;
          border-radius: 5px;
          cursor: pointer;
          font-size: 14px;
          font-weight: bold;
        ">Go Back</button>
      </div>
      <p style="margin: 20px 0 0 0; font-size: 12px; color: #adb5bd;">
        Powered by WebShield Security Extension
      </p>
    </div>
  `;

  const body = getSafeBody();
  if (!body) return;
  safeAppendChild(body, overlay);

  // Add event listeners
  document.getElementById('webshield-proceed').addEventListener('click', () => {
    overlay.remove();
  });

  document.getElementById('webshield-go-back').addEventListener('click', () => {
    window.history.back();
  });
}

// Enhanced SSL info display
function showSSLInfo(sslResult) {
  if (!SECURITY_CONFIG.showDetailedAlerts) return;

  const sslIndicator = document.createElement('div');
  sslIndicator.id = 'webshield-ssl-indicator';
  sslIndicator.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #28a745;
    color: white;
    padding: 10px 15px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    z-index: 999998;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    cursor: pointer;
  `;

  sslIndicator.innerHTML = `
    <div style="display: flex; align-items: center; gap: 8px;">
      <span>🔒</span>
      <span>SSL Valid</span>
      <span style="font-size: 10px;">✓</span>
    </div>
  `;

  sslIndicator.addEventListener('click', () => {
    showSSLDetails(sslResult, false);
  });

  const body = getSafeBody();
  if (!body) return;
  safeAppendChild(body, sslIndicator);

  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (sslIndicator.parentNode) {
      sslIndicator.remove();
    }
  }, 5000);
}

// Show a non-intrusive top-right badge for safe/low-risk pages
function showRiskIndicator(text = 'Low Risk') {
  try {
    const existing = document.getElementById('webshield-risk-indicator');
    if (existing) existing.remove();

    const badge = document.createElement('div');
    badge.id = 'webshield-risk-indicator';
    badge.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: #28a745;
      color: white;
      padding: 10px 14px;
      border-radius: 6px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 12px;
      z-index: 999998;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
      display: flex;
      gap: 8px;
      align-items: center;
      cursor: default;
    `;
    badge.innerHTML = `
      <span>✅</span>
      <span>${text}</span>
    `;

    const body = getSafeBody();
    if (body) {
      safeAppendChild(body, badge);
      setTimeout(() => {
        if (badge.parentNode) badge.remove();
      }, 5000);
    }
  } catch (_) { }
}

// Notify background to show a system notification immediately
function notifyBackground(level = 'warning', url = window.location.href) {
  try {
    chrome.runtime.sendMessage({ type: 'SHOW_SYSTEM_NOTIFICATION', url, level });
  } catch (_) { }
}

// Detect SPA URL changes and re-run analysis
function watchUrlChanges() {
  const recheck = () => initializeSecurityAnalysis();
  try {
    const _pushState = history.pushState;
    history.pushState = function () {
      const result = _pushState.apply(this, arguments);
      setTimeout(recheck, 0);
      return result;
    };
  } catch (_) { }
  try {
    const _replaceState = history.replaceState;
    history.replaceState = function () {
      const result = _replaceState.apply(this, arguments);
      setTimeout(recheck, 0);
      return result;
    };
  } catch (_) { }
  window.addEventListener('popstate', recheck);
}

// Enhanced SSL details display
function showSSLDetails(sslResult, isWarning = false) {
  const detailsOverlay = document.createElement('div');
  detailsOverlay.id = 'webshield-ssl-details';
  detailsOverlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0,0,0,0.8);
    z-index: 999999;
    display: flex;
    justify-content: center;
    align-items: center;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `;

  const bgColor = isWarning ? '#ffc107' : '#28a745';
  const icon = isWarning ? '⚠️' : '🔒';

  detailsOverlay.innerHTML = `
    <div style="
      max-width: 500px;
      background: white;
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    ">
      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px;">
        <span style="font-size: 24px;">${icon}</span>
        <h2 style="margin: 0; color: ${bgColor};">SSL Certificate Details</h2>
      </div>
      
      <div style="margin-bottom: 20px;">
        <p><strong>Status:</strong> <span style="color: ${isWarning ? '#ffc107' : '#28a745'};">${sslResult.valid ? 'Valid' : 'Invalid'}</span></p>
        ${sslResult.issuer ? `<p><strong>Issuer:</strong> ${sslResult.issuer}</p>` : ''}
        ${sslResult.expires ? `<p><strong>Expires:</strong> ${new Date(sslResult.expires).toLocaleDateString()}</p>` : ''}
        ${sslResult.error ? `<p><strong>Error:</strong> <span style="color: #dc3545;">${sslResult.error}</span></p>` : ''}
      </div>
      
      <button id="webshield-close-details" style="
        background: ${bgColor};
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        cursor: pointer;
        font-size: 14px;
      ">Close</button>
    </div>
  `;

  const body = getSafeBody();
  if (!body) return;
  safeAppendChild(body, detailsOverlay);

  document.getElementById('webshield-close-details').addEventListener('click', () => {
    detailsOverlay.remove();
  });
}



// Enhanced icon update function
function updateSafeBrowsingIcon(status) {
  try {
    chrome.runtime.sendMessage({ type: 'UPDATE_ICON', status }, (response) => {
      if (chrome.runtime.lastError) {
        console.error('WebShield: Icon update failed:', chrome.runtime.lastError.message);
      } else {
        console.log('WebShield: Icon updated to:', status);
      }
    });
  } catch (error) {
    console.error('WebShield: Icon update error:', error.message);
  }
}

// Enhanced error handling for API calls
function handleAPIError(error, context) {
  console.error(`WebShield: ${context} error:`, error);

  // Show user-friendly error message
  const errorMessage = document.createElement('div');
  errorMessage.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: #dc3545;
    color: white;
    padding: 10px 15px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 12px;
    z-index: 999998;
    box-shadow: 0 2px 10px rgba(0,0,0,0.2);
  `;

  errorMessage.textContent = `WebShield: ${context} failed. Please try again.`;
  const body = getSafeBody();
  if (body) {
    safeAppendChild(body, errorMessage);
  }

  setTimeout(() => {
    if (errorMessage.parentNode) {
      errorMessage.remove();
    }
  }, 5000);
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('WebShield Content: Received message:', message.type);

  switch (message.type) {
    case 'SHOW_ALERT':
      showAlert(message.message, message.level);
      break;

    case 'UPDATE_SECURITY_STATUS':
      updateSecurityStatus(message.status);
      break;

    case 'CLEAR_OVERLAYS':
      clearAllOverlays();
      break;
    case 'BLOCK_SITE':
      showWarningOverlay('block-site');
      break;
  }
});

// Show alert message
function showAlert(message, level = 'info') {
  const alertDiv = document.createElement('div');
  alertDiv.style.cssText = `
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: ${level === 'danger' ? '#dc3545' : level === 'warning' ? '#ffc107' : '#28a745'};
    color: white;
    padding: 15px 20px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    z-index: 999999;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    max-width: 400px;
    text-align: center;
  `;

  alertDiv.textContent = message;
  const body = getSafeBody();
  if (body) {
    safeAppendChild(body, alertDiv);
  }

  setTimeout(() => {
    if (alertDiv.parentNode) {
      alertDiv.remove();
    }
  }, 5000);
}

// Update security status
function updateSecurityStatus(status) {
  try {
    updateSafeBrowsingIcon(status);
  } catch (error) {
    console.error('WebShield: Security status update failed:', error.message);
  }
}

// Clear all overlays
function clearAllOverlays() {
  const overlays = document.querySelectorAll('[id^="webshield-"]');
  overlays.forEach(overlay => overlay.remove());
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  clearAllOverlays();
}); 
