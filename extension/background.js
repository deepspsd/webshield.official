// WebShield Extension Background Script

// Dynamic API endpoint detection (respects user override)
async function getAPIBaseURL() {
  try {
    const result = await new Promise((resolve) => {
      chrome.storage.sync.get({ api_base_override: null }, (res) => resolve(res));
    });
    const override = result && result.api_base_override;
    if (override && typeof override === 'string' && override.startsWith('http')) {
      return override.replace(/\/$/, '');
    }
  } catch (e) {
    // ignore
  }
  return "http://localhost:8000";
}

// Fallback endpoints for testing
const FALLBACK_ENDPOINTS = [
  "http://localhost:8000",                      // Local development (primary)
  "http://127.0.0.1:8000",                     // Alternative local
  "https://pggjs0c8-8000.inc1.devtunnels.ms"  // Remote tunnel (fallback)
];

let currentAPIBase = null; // Will be set after testing endpoints
let endpointTestInterval = null; // For periodic endpoint testing
let rateLimitMap = new Map(); // Rate limiting for API calls
const RATE_LIMIT_WINDOW = 30000; // 30s window to be more lenient
const MAX_REQUESTS_PER_WINDOW = 15; // Allow more requests
let isOfflineMode = false; // Track if we're in offline mode

let endpointTestInFlight = null; // Promise guard to avoid overlapping endpoint tests
const _endpointFailureLogTimestamps = new Map(); // key -> lastLogTs

function shouldLogEndpointFailure(key, windowMs = 15000) {
  const now = Date.now();
  const last = _endpointFailureLogTimestamps.get(key) || 0;
  if (now - last < windowMs) return false;
  _endpointFailureLogTimestamps.set(key, now);
  return true;
}

async function fetchJsonWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { method: 'GET', signal: controller.signal });
    if (!res.ok) {
      return { ok: false, status: res.status, data: null };
    }
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      // If health endpoint returns non-JSON for some reason, treat it as not ok.
      return { ok: false, status: res.status, data: null };
    }
    return { ok: true, status: res.status, data };
  } catch (e) {
    const name = (e && e.name) ? String(e.name) : '';
    if (name === 'AbortError') {
      return { ok: false, status: 0, data: null, timeout: true };
    }
    return { ok: false, status: 0, data: null, error: (e && e.message) ? String(e.message) : 'request_failed' };
  } finally {
    clearTimeout(timeoutId);
  }
}

// Private/Local IP patterns - skip scanning for these
const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/,
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^\[::1\]$/,
];

// Check if URL is private/local and should be skipped
function isPrivateOrLocalUrl(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // Check exact matches
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0') {
      return true;
    }

    // Check patterns
    for (const pattern of PRIVATE_IP_PATTERNS) {
      if (pattern.test(hostname)) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

// Enhanced endpoint testing with retry logic
async function testEndpoints() {
  if (endpointTestInFlight) {
    return endpointTestInFlight;
  }

  endpointTestInFlight = (async () => {
    console.log('WebShield: Testing API endpoints...');

    // Health endpoint paths to try (in order)
    // Backend mounts health under /api/health (router has /health and server includes it with prefix /api)
    const healthPaths = ['/api/health', '/health'];

    // Try dynamic endpoint first
    const dynamicEndpoint = await getAPIBaseURL();
    for (const healthPath of healthPaths) {
      const full = `${dynamicEndpoint}${healthPath}`;
      const result = await fetchJsonWithTimeout(full, 8000);
      if (result && result.ok && result.data && (result.data.status === 'healthy' || result.data.message || result.data.health)) {
        currentAPIBase = dynamicEndpoint;
        isOfflineMode = false;
        console.log(`WebShield: API connected at: ${full}`);

        // Store the detected API base URL in storage for popup access
        chrome.storage.sync.set({ detectedApiBase: dynamicEndpoint, webAppBase: dynamicEndpoint });

        // Start periodic endpoint testing
        startPeriodicEndpointTesting();

        return dynamicEndpoint;
      }
      if (shouldLogEndpointFailure(full)) {
        const msg = result && result.timeout ? 'timeout' : ((result && result.error) ? result.error : `HTTP ${result && result.status ? result.status : 'ERR'}`);
        console.log(`WebShield: ${full} failed:`, msg);
      }
    }

    // Try fallback endpoints
    for (const endpoint of FALLBACK_ENDPOINTS) {
      for (const healthPath of healthPaths) {
        const full = `${endpoint}${healthPath}`;
        const result = await fetchJsonWithTimeout(full, 8000);
        if (result && result.ok && result.data && (result.data.status === 'healthy' || result.data.message || result.data.health)) {
          currentAPIBase = endpoint;
          isOfflineMode = false;
          console.log(`WebShield: API connected at: ${full}`);

          // Store the detected API base URL in storage for popup access
          chrome.storage.sync.set({ detectedApiBase: endpoint, webAppBase: endpoint });

          // Start periodic endpoint testing
          startPeriodicEndpointTesting();

          return endpoint;
        }
        if (shouldLogEndpointFailure(full)) {
          const msg = result && result.timeout ? 'timeout' : ((result && result.error) ? result.error : `HTTP ${result && result.status ? result.status : 'ERR'}`);
          console.log(`WebShield: ${full} failed:`, msg);
        }
      }
    }

    console.log('WebShield: No working API endpoints found, switching to offline mode');
    currentAPIBase = null;
    isOfflineMode = true;
    return null;
  })();

  try {
    return await endpointTestInFlight;
  } finally {
    endpointTestInFlight = null;
  }
}

// Start periodic endpoint testing
function startPeriodicEndpointTesting() {
  if (endpointTestInterval) {
    clearInterval(endpointTestInterval);
  }

  endpointTestInterval = setInterval(async () => {
    if (currentAPIBase && !isOfflineMode) {
      try {
        // Prefer /api/health (FastAPI) and only then fall back to /health.
        const primary = await fetchJsonWithTimeout(`${currentAPIBase}/api/health`, 8000);
        if (primary && primary.ok) return;

        const legacy = await fetchJsonWithTimeout(`${currentAPIBase}/health`, 8000);
        if (legacy && legacy.ok) return;

        console.log('WebShield: Current endpoint failed, retesting all endpoints...');
        await testEndpoints();
      } catch (error) {
        console.log('WebShield: Endpoint health check failed, retesting...');
        await testEndpoints();
      }
    }
  }, 30000); // Check every 30 seconds
}

// Rate limiting function
function isRateLimited(url) {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  if (!rateLimitMap.has(url)) {
    rateLimitMap.set(url, []);
  }

  const requests = rateLimitMap.get(url);

  // Remove old requests outside the window
  const validRequests = requests.filter(timestamp => timestamp > windowStart);
  rateLimitMap.set(url, validRequests);

  if (validRequests.length >= MAX_REQUESTS_PER_WINDOW) {
    return true;
  }

  // Add current request
  validRequests.push(now);
  return false;
}

// Enhanced error handling with retry logic
async function makeAPIRequest(endpoint, options, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(endpoint, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          ...options.headers
        }
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        return await response.json();
      } else {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
    } catch (error) {
      console.log(`WebShield: API request attempt ${attempt} failed:`, error.message);

      if (attempt === maxRetries) {
        throw error;
      }

      // Wait before retry with exponential backoff
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, attempt) * 1000));
    }
  }
}

// Offline SSL certificate validation
function validateSSLOffline(url) {
  try {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol;
    const hostname = urlObj.hostname.toLowerCase();

    // Check if this is a local/private URL - these don't need SSL
    const isLocal = isPrivateOrLocalUrl(url);

    if (isLocal) {
      // Local development doesn't require SSL
      return {
        valid: true,
        issuer: 'Local Development',
        expires: null,
        error: null,
        details: {
          protocol: protocol.replace(':', '').toUpperCase(),
          domain: hostname,
          local_network: true,
          message: 'SSL not required for local development'
        }
      };
    }

    if (protocol === 'https:') {
      return {
        valid: true,
        issuer: 'Browser Validated',
        expires: null,
        error: null,
        details: {
          protocol: 'HTTPS',
          domain: hostname,
          offline_validation: true
        }
      };
    } else {
      // Non-local HTTP - this is a warning
      return {
        valid: false,
        issuer: null,
        expires: null,
        error: 'Non-HTTPS connection',
        details: {
          protocol: 'HTTP',
          domain: hostname,
          offline_validation: true
        }
      };
    }
  } catch (error) {
    return {
      valid: false,
      issuer: null,
      expires: null,
      error: 'Invalid URL format',
      details: {
        offline_validation: true,
        error: error.message
      }
    };
  }
}

// Offline threat detection
function detectThreatsOffline(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // Basic offline threat detection patterns
    const suspiciousPatterns = [
      'phishing', 'malware', 'virus', 'scam', 'fake',
      'suspicious', 'dangerous', 'malicious', 'fraud'
    ];

    const suspiciousKeywords = [
      'login', 'signin', 'account', 'password', 'credit',
      'bank', 'paypal', 'amazon', 'ebay', 'facebook'
    ];

    let threatScore = 0;
    let detectedThreats = [];

    // Check for suspicious patterns in URL
    for (const pattern of suspiciousPatterns) {
      if (hostname.includes(pattern)) {
        threatScore += 3;
        detectedThreats.push(`Suspicious keyword: ${pattern}`);
      }
    }

    // Check for typosquatting (basic)
    const commonDomains = ['google', 'facebook', 'amazon', 'paypal', 'ebay'];
    for (const domain of commonDomains) {
      if (hostname.includes(domain) && hostname !== domain) {
        const distance = levenshteinDistance(hostname, domain);
        if (distance <= 2) {
          threatScore += 2;
          detectedThreats.push(`Possible typosquatting: ${domain}`);
        }
      }
    }

    // Determine threat level
    let threatLevel = 'low';
    if (threatScore >= 5) {
      threatLevel = 'high';
    } else if (threatScore >= 2) {
      threatLevel = 'medium';
    }

    return {
      results: {
        threat_level: threatLevel,
        is_malicious: threatLevel === 'high',
        malicious_count: threatScore,
        suspicious_count: detectedThreats.length,
        total_engines: 1,
        detection_details: {
          offline_detection: true,
          detected_threats: detectedThreats,
          threat_score: threatScore
        }
      }
    };
  } catch (error) {
    return {
      results: {
        threat_level: 'unknown',
        is_malicious: false,
        malicious_count: 0,
        suspicious_count: 0,
        total_engines: 1,
        detection_details: {
          offline_detection: true,
          error: error.message
        }
      }
    };
  }
}

// Levenshtein distance for typosquatting detection
function levenshteinDistance(s1, s2) {
  const matrix = [];

  for (let i = 0; i <= s2.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= s1.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= s2.length; i++) {
    for (let j = 1; j <= s1.length; j++) {
      if (s2.charAt(i - 1) === s1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[s2.length][s1.length];
}

// Initialize endpoint testing
testEndpoints();



// Enhanced message listener with better error handling
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  console.log('WebShield: Received message:', msg.type);

  // Rate limiting check
  if (isRateLimited(msg.url || 'general')) {
    console.log('WebShield: Rate limited for URL:', msg.url);
    sendResponse({ error: 'Rate limited. Please try again later.' });
    return true;
  }

  switch (msg.type) {
    case 'CHECK_URL':
      checkUrl(msg.url, sendResponse);
      return true;

    case 'REPORT_URL':
      reportUrl(msg.url, msg.reason, sendResponse);
      return true;

    case 'GET_HISTORY':
      getHistory(sendResponse);
      return true;

    case 'SYNC_SETTINGS':
      syncSettings(msg.settings, sendResponse);
      return true;

    case 'THREAT_ALERT':
      showThreatNotification(msg.url, msg.level);
      return true;
    case 'SHOW_SYSTEM_NOTIFICATION':
      // Explicit request from other contexts to show a system notification
      if (msg.url && msg.level) {
        showThreatNotification(msg.url, msg.level);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: 'Missing url or level' });
      }
      return true;

    case 'GET_TAB_ID':
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        sendResponse(tabs[0]?.id);
      });
      return true;

    case 'CLOSE_TAB':
      if (msg.tabId) {
        chrome.tabs.remove(msg.tabId);
      }
      return true;

    case 'CHECK_SSL_CERTIFICATE':
      checkSSLCertificate(msg.url, sendResponse);
      return true;

    case 'GET_SSL_DETAILS':
      getSSLDetails(msg.url, sendResponse);
      return true;

    case 'SHOW_THREAT_ALERT':
      // Enhanced fallback threat alert with better logging
      console.log('WebShield: Fallback threat alert:', msg.url, msg.level);
      showEnhancedThreatAlert(msg.url, msg.level);
      return true;

    case 'UPDATE_ICON':
      updateExtensionIcon(msg.status);
      sendResponse({ success: true });
      return true;



    case 'GET_EXTENSION_STATUS':
      getExtensionStatus(sendResponse);
      return true;

    case 'GET_STATUS':
      // Alias for legacy callers in popup.js
      getExtensionStatus(sendResponse);
      return true;

    case 'CLEAR_CACHE':
      clearCache(sendResponse);
      return true;

    default:
      console.log('WebShield: Unknown message type:', msg.type);
      sendResponse({ error: 'Unknown message type' });
      return true;
  }
});

// Enhanced SSL certificate validation with offline fallback
async function checkSSLCertificate(url, cb) {
  try {
    // Validate URL format
    if (!url || !url.startsWith('http')) {
      cb({ error: 'Invalid URL format' });
      return;
    }

    // Skip SSL check for localhost and private network IPs
    if (isPrivateOrLocalUrl(url)) {
      console.log('WebShield: Skipping SSL check for local/private URL:', url);
      cb({
        valid: true,
        issuer: 'Local Development',
        expires: null,
        error: null,
        details: {
          local_network: true,
          message: 'Local/private network - SSL check skipped'
        }
      });
      return;
    }

    if (!currentAPIBase || isOfflineMode) {
      console.log('WebShield: Using offline SSL validation');
      const offlineResult = validateSSLOffline(url);
      cb(offlineResult);
      return;
    }

    console.log('WebShield: Checking SSL certificate for:', url);

    // Use the main scan endpoint which includes SSL analysis
    const requestBody = {
      url: url,
      user_email: null
    };

    const data = await makeAPIRequest(
      `${currentAPIBase}/api/scan/scan`,
      {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }
    );

    // Handle immediate results
    if (data.results && data.results.detection_details?.ssl_analysis) {
      const sslAnalysis = data.results.detection_details.ssl_analysis;
      console.log('WebShield: SSL analysis completed');

      const result = {
        valid: sslAnalysis.valid || false,
        issuer: sslAnalysis.issuer || null,
        expires: sslAnalysis.expires || null,
        error: sslAnalysis.error || null,
        details: sslAnalysis,
        scan_id: data.scan_id
      };

      cb(result);
      return;
    }

    // Handle processing status
    if (data.status === 'processing' && data.scan_id) {
      console.log('WebShield: SSL scan processing, polling for results...');
      await pollSSLResults(data.scan_id, cb);
      return;
    }

    // Handle errors
    if (data.status === 'error') {
      console.error('WebShield: SSL scan failed:', data.error);
      cb({ error: data.error || 'SSL analysis failed' });
      return;
    }

    // Fallback to offline validation
    console.log('WebShield: Falling back to offline SSL validation');
    const offlineResult = validateSSLOffline(url);
    cb(offlineResult);

  } catch (e) {
    console.error('WebShield: SSL check error:', e);
    console.log('WebShield: Falling back to offline SSL validation');
    const offlineResult = validateSSLOffline(url);
    cb(offlineResult);
  }
}

// Polling function for SSL results
async function pollSSLResults(scanId, cb, attempt = 1) {
  const maxAttempts = 5;
  const baseDelay = 1000;

  try {
    console.log(`WebShield: SSL polling attempt ${attempt}/${maxAttempts}`);

    const resultData = await makeAPIRequest(
      `${currentAPIBase}/api/scan/scan/${scanId}`,
      { method: 'GET' }
    );

    if (resultData.results && resultData.results.detection_details?.ssl_analysis) {
      const sslAnalysis = resultData.results.detection_details.ssl_analysis;
      console.log('WebShield: SSL analysis completed via polling');

      const result = {
        valid: sslAnalysis.valid || false,
        issuer: sslAnalysis.issuer || null,
        expires: sslAnalysis.expires || null,
        error: sslAnalysis.error || null,
        details: sslAnalysis,
        scan_id: scanId
      };

      cb(result);
      return;
    }

    if (resultData.status === 'error') {
      cb({ error: resultData.error || 'SSL analysis failed' });
      return;
    }

    // Continue polling if still processing
    if (resultData.status === 'processing' && attempt < maxAttempts) {
      const delay = baseDelay * Math.pow(1.5, attempt - 1);
      setTimeout(() => {
        pollSSLResults(scanId, cb, attempt + 1);
      }, delay);
      return;
    }

    // Max attempts reached or unexpected status
    cb({ error: 'SSL analysis timeout' });

  } catch (error) {
    console.error('WebShield: SSL polling error:', error);

    if (attempt < maxAttempts) {
      const delay = baseDelay * Math.pow(1.5, attempt - 1);
      setTimeout(() => {
        pollSSLResults(scanId, cb, attempt + 1);
      }, delay);
    } else {
      cb({ error: 'SSL analysis failed' });
    }
  }
}

// Get detailed SSL certificate information
async function getSSLDetails(url, cb) {
  if (!currentAPIBase || isOfflineMode) {
    console.log('WebShield: Using offline SSL details');
    const offlineResult = validateSSLOffline(url);
    cb({
      ssl_valid: offlineResult.valid,
      ssl_analysis: offlineResult.details,
      threat_level: 'unknown',
      malicious_count: 0,
      suspicious_count: 0,
      total_engines: 1
    });
    return;
  }

  try {
    // Fix the request format to match the API expectations
    const requestBody = {
      url: url,
      user_email: null,
      force_rescan: true  // Always get fresh results
    };

    const data = await makeAPIRequest(
      `${currentAPIBase}/api/scan/scan`,
      {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }
    );

    if (data.results) {
      cb({
        ssl_valid: data.results.ssl_valid,
        ssl_analysis: data.results.detection_details?.ssl_analysis || {},
        threat_level: data.results.threat_level,
        malicious_count: data.results.malicious_count,
        suspicious_count: data.results.suspicious_count,
        total_engines: data.results.total_engines
      });
    } else {
      cb({ error: 'SSL details not available' });
    }
  } catch (e) {
    console.error('SSL details error:', e);
    console.log('WebShield: Falling back to offline SSL details');
    const offlineResult = validateSSLOffline(url);
    cb({
      ssl_valid: offlineResult.valid,
      ssl_analysis: offlineResult.details,
      threat_level: 'unknown',
      malicious_count: 0,
      suspicious_count: 0,
      total_engines: 1
    });
  }
}

// Enhanced real-time URL check with improved polling and error handling
async function checkUrl(url, cb) {
  try {
    // Validate URL format
    if (!url || !url.startsWith('http')) {
      cb({ error: 'Invalid URL format' });
      return;
    }

    // Skip scanning for localhost and private network IPs
    if (isPrivateOrLocalUrl(url)) {
      console.log('WebShield: Skipping local/private URL:', url);
      cb({
        results: {
          threat_level: 'low',
          is_malicious: false,
          malicious_count: 0,
          suspicious_count: 0,
          total_engines: 1,
          detection_details: {
            local_network: true,
            message: 'Local/private network - trusted by default'
          }
        }
      });
      return;
    }

    if (!currentAPIBase || isOfflineMode) {
      console.log('WebShield: Using offline threat detection');
      const offlineResult = detectThreatsOffline(url);
      handleThreatDetection(offlineResult, url);
      cb(offlineResult);
      return;
    }

    // Prepare request body - always force fresh scan
    const requestBody = {
      url: url,
      user_email: null,
      force_rescan: true  // Always get fresh results
    };

    console.log('WebShield: Starting scan for URL:', url);

    // Initial scan request
    const data = await makeAPIRequest(
      `${currentAPIBase}/api/scan/scan`,
      {
        method: 'POST',
        body: JSON.stringify(requestBody)
      }
    );

    // Handle immediate results
    if (data.results) {
      console.log('WebShield: Scan completed immediately');
      handleThreatDetection(data, url);
      cb(data);
      return;
    }

    // Handle processing status with improved polling
    if (data.status === 'processing' && data.scan_id) {
      console.log('WebShield: Scan processing, polling for results...');
      await pollScanResults(data.scan_id, url, cb);
      return;
    }

    // Handle other statuses
    if (data.status === 'error') {
      console.error('WebShield: Scan failed:', data.error || 'Unknown error');
      cb({ error: data.error || 'Scan failed' });
      return;
    }

    // Fallback for unexpected responses
    cb(data);

  } catch (e) {
    console.error('WebShield: URL check error:', e);
    console.log('WebShield: Falling back to offline threat detection');
    const offlineResult = detectThreatsOffline(url);
    handleThreatDetection(offlineResult, url);
    cb(offlineResult);
  }
}

// Improved polling function with exponential backoff
async function pollScanResults(scanId, url, cb, attempt = 1) {
  const maxAttempts = 8;
  const baseDelay = 500; // 0.5 second
  const maxDelay = 4000;  // 4 seconds

  try {
    console.log(`WebShield: Polling attempt ${attempt}/${maxAttempts} for scan ${scanId}`);

    const resultData = await makeAPIRequest(
      `${currentAPIBase}/api/scan/scan/${scanId}`,
      { method: 'GET' }
    );

    if (resultData.results) {
      console.log('WebShield: Scan completed successfully');
      handleThreatDetection(resultData, url);
      cb(resultData);
      return;
    }

    if (resultData.status === 'error') {
      console.error('WebShield: Scan failed during polling:', resultData.error);
      cb({ error: resultData.error || 'Scan failed' });
      return;
    }

    // Continue polling if still processing
    if (resultData.status === 'processing' && attempt < maxAttempts) {
      const delay = Math.min(baseDelay * Math.pow(1.35, attempt - 1), maxDelay);
      console.log(`WebShield: Scan still processing, retrying in ${delay}ms`);

      setTimeout(() => {
        pollScanResults(scanId, url, cb, attempt + 1);
      }, delay);
      return;
    }

    // Max attempts reached
    if (attempt >= maxAttempts) {
      console.warn('WebShield: Max polling attempts reached');
      cb({ error: 'Scan timeout - please try again' });
      return;
    }

    // Unexpected status
    cb({ error: 'Unexpected scan status' });

  } catch (error) {
    console.error('WebShield: Polling error:', error);

    if (attempt < maxAttempts) {
      const delay = Math.min(baseDelay * Math.pow(1.35, attempt - 1), maxDelay);
      setTimeout(() => {
        pollScanResults(scanId, url, cb, attempt + 1);
      }, delay);
    } else {
      cb({ error: 'Failed to get scan results' });
    }
  }
}

// Calculate threat level based on VirusTotal results and SSL
// Rules:
// - HIGH/BLOCK: No SSL OR >2 engines flag malicious/suspicious
// - MODERATE: 1-2 engines flag malicious/suspicious  
// - LOW/SAFE: SSL valid AND 0 engines flag
function calculateThreatLevel(results, sslValid = true) {
  const maliciousCount = results?.malicious_count || 0;
  const suspiciousCount = results?.suspicious_count || 0;
  const totalFlags = maliciousCount + suspiciousCount;

  // No SSL = High risk
  if (sslValid === false) {
    return { level: 'high', reason: 'No SSL certificate' };
  }

  // More than 2 engines flagged = High risk (block)
  if (totalFlags > 2) {
    return { level: 'high', reason: `${totalFlags} engines flagged as malicious/suspicious` };
  }

  // 1-2 engines flagged = Moderate risk
  if (totalFlags >= 1) {
    return { level: 'moderate', reason: `${totalFlags} engine(s) flagged` };
  }

  // 0 engines and SSL valid = Safe
  return { level: 'low', reason: 'No threats detected' };
}

// Centralized threat detection handling
function handleThreatDetection(result, url) {
  if (!result.results) return;

  const maliciousCount = result.results.malicious_count || 0;
  const suspiciousCount = result.results.suspicious_count || 0;
  const sslValid = result.results.detection_details?.ssl_analysis?.valid !== false;

  // Calculate threat level using our rules
  const { level, reason } = calculateThreatLevel(result.results, sslValid);

  // Store scan ID for View Details functionality
  const scanId = result.scan_id || result.results?.scan_id;
  if (scanId) {
    chrome.storage.local.set({
      lastScanId: scanId,
      lastScanUrl: url,
      lastScanTime: Date.now(),
      lastThreatLevel: level,
      lastThreatReason: reason
    });
    console.log('WebShield: Stored scan ID:', scanId, 'Threat Level:', level, 'Reason:', reason);
  }

  // Handle based on calculated level
  if (level === 'high') {
    // High risk - show notification and block
    showThreatNotification(url, 'high');
    chrome.runtime.sendMessage({
      type: 'THREAT_ALERT',
      url,
      level: 'high',
      scanId: scanId,
      details: result.results,
      reason: reason
    });
    updateExtensionIcon('danger');
    console.log(`WebShield: HIGH RISK - ${reason}, URL: ${url}`);
  } else if (level === 'moderate') {
    // Moderate risk - show warning but don't block
    showThreatNotification(url, 'moderate');
    chrome.runtime.sendMessage({
      type: 'THREAT_ALERT',
      url,
      level: 'moderate',
      scanId: scanId,
      details: result.results,
      reason: reason
    });
    updateExtensionIcon('warning');
    console.log(`WebShield: MODERATE RISK - ${reason}, URL: ${url}`);
  } else {
    // Safe - update icon
    updateExtensionIcon('safe');
    console.log(`WebShield: SAFE - ${reason}, URL: ${url}`);
  }
}

// Report suspicious URL with enhanced error handling
async function reportUrl(url, reason, cb) {
  if (!currentAPIBase || isOfflineMode) {
    console.log('WebShield: Offline mode - cannot report URL');
    cb({ error: 'Cannot report URL in offline mode' });
    return;
  }

  try {
    // Backend endpoint not present; save locally for now
    const key = 'reported_urls';
    chrome.storage.local.get({ [key]: [] }, (res) => {
      const list = Array.isArray(res[key]) ? res[key] : [];
      list.push({ url, reason, ts: Date.now() });
      chrome.storage.local.set({ [key]: list }, () => cb({ success: true }));
    });
  } catch (e) {
    console.error('Report URL error:', e);
    cb({ error: 'Network error' });
  }
}

// Get scan history with enhanced error handling
async function getHistory(cb) {
  try {
    if (!currentAPIBase || isOfflineMode) {
      console.log('WebShield: Offline mode - no history available');
      cb([]);
      return;
    }

    const data = await makeAPIRequest(
      `${currentAPIBase}/api/admin/user_scans?limit=20`,
      { method: 'GET' }
    );
    cb(data);
  } catch (e) {
    console.error('Get history error:', e);
    cb([]);
  }
}

// Sync settings with enhanced error handling
function syncSettings(settings, cb) {
  chrome.storage.sync.set({ settings }, () => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Settings sync error:', chrome.runtime.lastError);
      cb({ error: 'Failed to sync settings' });
    } else {
      cb({ success: true });
    }
  });
}

// Enhanced threat notification with better error handling
function showThreatNotification(url, level) {
  console.log(`WebShield: Threat detected - Level: ${level}, URL: ${url}`);

  // Create notification with better error handling
  try {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'WebShield Threat Detected',
      message: `Detected ${level} risk site: ${new URL(url).hostname}`,
      priority: 2
    }, (notificationId) => {
      if (chrome.runtime.lastError) {
        console.error('WebShield: Notification error:', chrome.runtime.lastError);
        // Fallback: show alert in popup or use a different method
        chrome.runtime.sendMessage({
          type: 'SHOW_THREAT_ALERT',
          url: url,
          level: level
        });
      } else {
        console.log('WebShield: Notification created successfully:', notificationId);
      }
    });
  } catch (error) {
    console.error('WebShield: Notification creation failed:', error);
    // Fallback: show alert in popup
    chrome.runtime.sendMessage({
      type: 'SHOW_THREAT_ALERT',
      url: url,
      level: level
    });
  }

  // Also update the extension icon to show danger state
  updateExtensionIcon('danger');
}

// Enhanced threat alert with more detailed information
function showEnhancedThreatAlert(url, level) {
  const hostname = new URL(url).hostname;
  const alertMessage = `⚠️ WebShield Security Alert ⚠️\n\n` +
    `Site: ${hostname}\n` +
    `Threat Level: ${level.toUpperCase()}\n` +
    `Time: ${new Date().toLocaleString()}\n\n` +
    `This site has been flagged as potentially dangerous. Proceed with caution.`;

  // Try to show in popup first, then fallback to console
  try {
    chrome.runtime.sendMessage({
      type: 'SHOW_ALERT',
      message: alertMessage,
      level: level
    });
  } catch (error) {
    console.warn('WebShield Enhanced Alert:', alertMessage);
  }
}

// Update extension icon based on status with enhanced error handling
function updateExtensionIcon(status) {
  const iconMap = {
    'safe': 'icons/icon48.png',
    'warning': 'icons/icon48.png', // You can create warning icon
    'danger': 'icons/icon48.png',   // You can create danger icon

  };

  const iconPath = iconMap[status] || 'icons/icon48.png';

  // Check if chrome.action is available
  if (typeof chrome !== 'undefined' && chrome.action) {
    try {
      chrome.action.setIcon({
        path: iconPath
      }, () => {
        if (chrome.runtime.lastError) {
          console.error('WebShield: Icon update error:', chrome.runtime.lastError.message);
        } else {
          console.log(`WebShield: Icon updated to ${status} state`);
        }
      });
    } catch (error) {
      console.error('WebShield: Icon update failed:', error.message);
    }
  } else {
    console.log('WebShield: Chrome action API not available for icon update');
  }
}

// Context menu for quick scan/report with enhanced functionality
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'scan-url',
    title: 'Scan this URL with WebShield',
    contexts: ['link']
  });
  chrome.contextMenus.create({
    id: 'report-url',
    title: 'Report this site as suspicious',
    contexts: ['link']
  });
  chrome.contextMenus.create({
    id: 'check-ssl',
    title: 'Check SSL Certificate',
    contexts: ['link']
  });

  // Initialize API endpoints on extension install
  testEndpoints().then(() => {
    console.log('WebShield: Extension installed, API endpoints tested');
  });
});

// Initialize API endpoints when extension starts
chrome.runtime.onStartup.addListener(() => {
  testEndpoints().then(() => {
    console.log('WebShield: Extension started, API endpoints tested');
  });
});

// Also test endpoints when the background script loads
testEndpoints().then(() => {
  console.log('WebShield: Background script loaded, API endpoints tested');
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'scan-url') {
    chrome.runtime.sendMessage({ type: 'CHECK_URL', url: info.linkUrl });
  }
  if (info.menuItemId === 'report-url') {
    chrome.runtime.sendMessage({ type: 'REPORT_URL', url: info.linkUrl, reason: 'User reported from extension' });
  }
  if (info.menuItemId === 'check-ssl') {
    chrome.runtime.sendMessage({ type: 'CHECK_SSL_CERTIFICATE', url: info.linkUrl });
  }
});



// Get extension status
function getExtensionStatus(cb) {
  chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
    cb({
      enabled: settings.extensionEnabled,
      apiBase: currentAPIBase,
      endpoints: FALLBACK_ENDPOINTS, // Use fallback endpoints for status
      offlineMode: isOfflineMode
    });
  });
}

// Clear cache and reset state
function clearCache(cb) {
  rateLimitMap.clear();
  currentAPIBase = null;
  isOfflineMode = false;
  if (endpointTestInterval) {
    clearInterval(endpointTestInterval);
    endpointTestInterval = null;
  }

  // Retest endpoints
  testEndpoints().then(() => {
    cb({ success: true, message: 'Cache cleared and endpoints retested' });
  });
}

// Cleanup on extension unload (guarded for MV3)
if (chrome.runtime.onSuspend && chrome.runtime.onSuspend.addListener) {
  chrome.runtime.onSuspend.addListener(() => {
    if (endpointTestInterval) {
      clearInterval(endpointTestInterval);
    }
    rateLimitMap.clear();
    console.log('WebShield: Extension suspended, cleaned up resources');
  });
}
