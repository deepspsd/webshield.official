// WebShield Extension Popup Script

// Dynamic URL detection function
function getWebAppBaseURL() {
  return new Promise((resolve) => {
    chrome.storage.sync.get({ webAppBase: 'http://localhost:8000' }, (result) => {
      // Always return base without trailing slash
      const base = (result.webAppBase || 'http://localhost:8000').replace(/\/$/, '');
      resolve(base);
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  // Initialize popup
  initializePopup();
  setupButtonListeners();

  // Test scan ID storage
  testScanIdStorage();

  // Check API status periodically
  checkAPIStatus();
  setInterval(checkAPIStatus, 30000); // Check every 30 seconds
});

// Check API status and update UI
function checkAPIStatus() {
  chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (status) => {
    if (status) {
      console.log('WebShield: API Status:', status);

      // Update offline indicator if needed
      const offlineInfo = document.getElementById('offline-info');
      if (offlineInfo) {
        if (status.offlineMode) {
          offlineInfo.style.display = 'block';
        } else {
          offlineInfo.style.display = 'none';
        }
      }

      // Store API status for other components
      chrome.storage.local.set({
        apiStatus: status,
        lastStatusCheck: Date.now()
      });


    }
  });
}

// Test function to verify scan ID storage
function testScanIdStorage() {
  console.log('🧪 Testing scan ID storage...');

  // Test storing a scan ID
  const testScanId = 'test-scan-id-12345';
  chrome.storage.local.set({
    lastScanId: testScanId,
    lastScanUrl: 'https://example.com',
    lastScanTime: Date.now()
  }, () => {
    console.log('🧪 Stored test scan ID:', testScanId);

    // Test retrieving the scan ID
    chrome.storage.local.get(['lastScanId', 'lastScanUrl', 'lastScanTime'], (result) => {
      console.log('🧪 Retrieved from storage:', result);
      if (result.lastScanId === testScanId) {
        console.log('✅ Scan ID storage test passed');
      } else {
        console.error('❌ Scan ID storage test failed');
      }

      // Clean up test data
      chrome.storage.local.remove(['lastScanId', 'lastScanUrl', 'lastScanTime']);
    });
  });
}

// Initialize popup with current page analysis
function initializePopup() {
  // Load extension state
  loadExtensionState();

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0]?.url;
    if (!url) {
      showErrorState('No active tab found');
      return;
    }

    // Update current URL display
    document.getElementById('current-url').textContent = url;

    // Analyze current page only if extension is enabled
    chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
      if (settings.extensionEnabled) {
        analyzeCurrentPage(url);
      } else {
        showDisabledState();
      }
    });
  });
}

// Load extension state from storage
function loadExtensionState() {
  chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
    updateToggleUI(settings.extensionEnabled);
  });

  // Clear old scan IDs (older than 1 hour)
  chrome.storage.local.get(['lastScanTime', 'lastSSLScanTime'], (data) => {
    const oneHourAgo = Date.now() - (60 * 60 * 1000);

    if (data.lastScanTime && data.lastScanTime < oneHourAgo) {
      chrome.storage.local.remove(['lastScanId', 'lastScanUrl', 'lastScanTime']);
      console.log('WebShield: Cleared old scan ID data');
    }

    if (data.lastSSLScanTime && data.lastSSLScanTime < oneHourAgo) {
      chrome.storage.local.remove(['lastSSLScanId', 'lastSSLScanUrl', 'lastSSLScanTime']);
      console.log('WebShield: Cleared old SSL scan ID data');
    }
  });
}

// Update toggle UI based on state
function updateToggleUI(enabled) {
  const toggleBtn = document.getElementById('extension-toggle');

  if (enabled) {
    toggleBtn.classList.remove('inactive');
    toggleBtn.classList.add('active');
  } else {
    toggleBtn.classList.remove('active');
    toggleBtn.classList.add('inactive');
  }
}

// Show disabled state
function showDisabledState() {
  const sslIcon = document.getElementById('ssl-icon');
  const sslStatus = document.getElementById('ssl-status');
  const threatIcon = document.getElementById('threat-icon');
  const threatLevel = document.getElementById('threat-level');
  const reputation = document.getElementById('domain-reputation');

  sslIcon.textContent = '⏸️';
  sslStatus.textContent = 'Extension Disabled';
  sslStatus.style.color = '#6c757d';

  threatIcon.textContent = '⏸️';
  threatLevel.textContent = 'Extension Disabled';
  threatLevel.style.color = '#6c757d';

  reputation.textContent = 'Extension Disabled';
  reputation.style.color = '#6c757d';

  // Update alerts section
  updateAlertsSection('disabled');
}

// Show error state
function showErrorState(message) {
  const sslIcon = document.getElementById('ssl-icon');
  const sslStatus = document.getElementById('ssl-status');
  const threatIcon = document.getElementById('threat-icon');
  const threatLevel = document.getElementById('threat-level');
  const reputation = document.getElementById('domain-reputation');

  sslIcon.textContent = '❌';
  sslStatus.textContent = 'Error';
  sslStatus.style.color = '#dc3545';

  threatIcon.textContent = '❌';
  threatLevel.textContent = 'Error';
  threatLevel.style.color = '#dc3545';

  reputation.textContent = message;
  reputation.style.color = '#dc3545';

  // Update alerts section
  updateAlertsSection('error', message);
}

// Analyze current page and update UI
function analyzeCurrentPage(url) {
  console.log('WebShield: Analyzing current page:', url);

  // Validate URL
  if (!url || !url.startsWith('http')) {
    showErrorState('Invalid URL format');
    return;
  }

  // Show loading state
  showLoadingState();

  // Track completion status
  let sslCompleted = false;
  let threatCompleted = false;

  function checkCompletion() {
    if (sslCompleted && threatCompleted) {
      hideLoadingState();
    }
  }

  // Update SSL status with enhanced error handling
  chrome.runtime.sendMessage({ type: 'CHECK_SSL_CERTIFICATE', url }, (sslResult) => {
    console.log('WebShield: SSL check result:', sslResult);
    updateSSLStatus(sslResult);
    sslCompleted = true;
    checkCompletion();

    // Store SSL scan_id for View Details functionality
    if (sslResult && sslResult.scan_id) {
      chrome.storage.local.set({
        lastSSLScanId: sslResult.scan_id,
        lastSSLScanUrl: url,
        lastSSLScanTime: Date.now()
      });
      console.log('WebShield: Stored SSL scan ID:', sslResult.scan_id);
    }
  });

  // Update threat level with enhanced error handling
  chrome.runtime.sendMessage({ type: 'CHECK_URL', url }, (result) => {
    console.log('WebShield: Threat check result:', result);
    updateThreatStatus(result);
    threatCompleted = true;
    checkCompletion();

    // Store scan_id for View Details functionality
    if (result && result.scan_id) {
      chrome.storage.local.set({
        lastScanId: result.scan_id,
        lastScanUrl: url,
        lastScanTime: Date.now()
      });
      console.log('WebShield: Stored scan ID in popup:', result.scan_id);
    }

    // Also store scan_id if it's in the results
    if (result && result.results && result.results.scan_id) {
      chrome.storage.local.set({
        lastScanId: result.results.scan_id,
        lastScanUrl: url,
        lastScanTime: Date.now()
      });
      console.log('WebShield: Stored scan ID from results:', result.results.scan_id);
    }
  });
}

// Update SSL status with enhanced details and better visual feedback
function updateSSLStatus(sslResult) {
  const sslIcon = document.getElementById('ssl-icon');
  const sslStatus = document.getElementById('ssl-status');

  if (!sslIcon || !sslStatus) return;

  // Clear any previous styling
  sslIcon.className = '';
  sslStatus.className = '';

  if (sslResult?.error) {
    sslIcon.innerHTML = '<span style="color: #dc3545; font-size: 16px;">&#10060;</span>'; // ❌
    sslStatus.textContent = 'SSL Error';
    sslStatus.style.color = '#dc3545';
    sslStatus.style.fontWeight = 'bold';
    console.error('WebShield: SSL check error:', sslResult.error);
    return;
  }

  if (sslResult?.valid) {
    sslIcon.innerHTML = '<span style="color: #28a745; font-size: 16px;">&#128274;</span>'; // 🔒

    // Enhanced status text with more details
    let statusText = 'SSL Valid';
    let statusColor = '#28a745';
    let statusStyle = 'normal';

    if (sslResult.details?.offline_validation) {
      statusText = 'SSL Valid (Offline)';
      statusColor = '#6c757d';
    } else if (sslResult.issuer) {
      // Truncate long issuer names
      const issuer = sslResult.issuer.length > 20 ?
        sslResult.issuer.substring(0, 20) + '...' :
        sslResult.issuer;
      statusText = `SSL Valid - ${issuer}`;
    }

    sslStatus.textContent = statusText;
    sslStatus.style.color = statusColor;
    sslStatus.style.fontWeight = statusStyle;

    // Add success animation
    sslIcon.style.animation = 'sslSuccess 0.5s ease-in-out';

    // Show additional info if available
    if (sslResult.expires) {
      console.log('WebShield: SSL certificate expires:', sslResult.expires);
    }
  } else {
    sslIcon.innerHTML = '<span style="color: #dc3545; font-size: 16px;">&#9888;</span>'; // ⚠️
    sslStatus.textContent = sslResult.details?.offline_validation ? 'SSL Invalid (Offline)' : 'SSL Invalid';
    sslStatus.style.color = '#dc3545';
    sslStatus.style.fontWeight = 'bold';

    // Add warning animation
    sslIcon.style.animation = 'sslWarning 0.5s ease-in-out';
  }

  // Store SSL result for View Details
  if (sslResult && sslResult.scan_id) {
    chrome.storage.local.set({ lastSSLScanId: sslResult.scan_id });
  }

  // Add CSS animations if not already present
  addSSLAnimations();
}

// Add SSL animations to the page
function addSSLAnimations() {
  if (document.getElementById('webshield-ssl-animations')) return;

  const style = document.createElement('style');
  style.id = 'webshield-ssl-animations';
  style.textContent = `
    @keyframes sslSuccess {
      0% { transform: scale(1); }
      50% { transform: scale(1.2); }
      100% { transform: scale(1); }
    }
    
    @keyframes sslWarning {
      0% { transform: scale(1); }
      25% { transform: scale(1.1) rotate(-5deg); }
      50% { transform: scale(1.1) rotate(5deg); }
      75% { transform: scale(1.1) rotate(-5deg); }
      100% { transform: scale(1); }
    }
    
    @keyframes threatAlert {
      0% { background-color: rgba(220, 53, 69, 0.1); }
      50% { background-color: rgba(220, 53, 69, 0.3); }
      100% { background-color: rgba(220, 53, 69, 0.1); }
    }
    
    @keyframes scanComplete {
      0% { opacity: 0; transform: translateY(-10px); }
      100% { opacity: 1; transform: translateY(0); }
    }
  `;
  document.head.appendChild(style);
}

// Update threat status with enhanced visual feedback
// Rules:
// - HIGH/BLOCK: >2 engines flag malicious/suspicious
// - MODERATE: 1-2 engines flag (warning, no block)
// - SAFE: 0 engines flag
function updateThreatStatus(threatResult) {
  const threatIcon = document.getElementById('threat-icon');
  const threatLevel = document.getElementById('threat-level');
  const reputation = document.getElementById('domain-reputation');

  if (!threatIcon || !threatLevel || !reputation) return;

  // Clear any previous styling
  threatIcon.className = '';
  threatLevel.className = '';
  reputation.className = '';

  if (threatResult?.results) {
    const maliciousCount = threatResult.results.malicious_count || 0;
    const suspiciousCount = threatResult.results.suspicious_count || 0;
    const totalEngines = threatResult.results.total_engines || 1;
    const isOffline = threatResult.results.detection_details?.offline_detection;
    const totalFlags = maliciousCount + suspiciousCount;

    // Apply new threat level rules
    if (totalFlags > 2) {
      // HIGH RISK: More than 2 engines flagged
      threatIcon.innerHTML = '<span style="color: #dc3545; font-size: 16px;">&#128680;</span>'; // 🚨
      threatLevel.textContent = isOffline ? 'High Risk (Offline)' : 'High Risk';
      threatLevel.style.color = '#dc3545';
      threatLevel.style.fontWeight = 'bold';
      reputation.textContent = `${totalFlags}/${totalEngines} engines detected threats`;
      reputation.style.color = '#dc3545';

      // Add danger animation
      threatIcon.style.animation = 'threatAlert 1s ease-in-out infinite';

      updateAlertsSection('high', `${totalFlags}/${totalEngines} engines flagged`);

    } else if (totalFlags >= 1) {
      // MODERATE RISK: 1-2 engines flagged (warning but NO blocking)
      threatIcon.innerHTML = '<span style="color: #ffc107; font-size: 16px;">&#9888;</span>'; // ⚠️
      threatLevel.textContent = isOffline ? 'Moderate Risk (Offline)' : 'Moderate Risk';
      threatLevel.style.color = '#ffc107';
      threatLevel.style.fontWeight = 'bold';
      reputation.textContent = `${totalFlags}/${totalEngines} engine(s) detected issues`;
      reputation.style.color = '#ffc107';

      // Add warning animation
      threatIcon.style.animation = 'sslWarning 0.5s ease-in-out';

      updateAlertsSection('medium', `${totalFlags}/${totalEngines} engine(s) flagged`);

    } else {
      // SAFE: 0 engines flagged
      threatIcon.innerHTML = '<span style="color: #28a745; font-size: 16px;">&#9989;</span>'; // ✅
      threatLevel.textContent = isOffline ? 'Safe (Offline)' : 'Safe';
      threatLevel.style.color = '#28a745';
      threatLevel.style.fontWeight = 'normal';

      // Enhanced reputation text
      if (isOffline) {
        reputation.textContent = 'Offline analysis - No threats detected';
        reputation.style.color = '#6c757d';
      } else {
        reputation.textContent = `0/${totalEngines} engines - Clean`;
        reputation.style.color = '#28a745';
      }

      // Add success animation
      threatIcon.style.animation = 'sslSuccess 0.5s ease-in-out';

      updateAlertsSection('safe');
    }

    // Add scan completion animation to the entire analysis section
    const analysisSection = document.querySelector('.page-analysis');
    if (analysisSection) {
      analysisSection.style.animation = 'scanComplete 0.5s ease-in-out';
    }

  } else if (threatResult?.error) {
    threatIcon.innerHTML = '<span style="color: #dc3545; font-size: 16px;">&#10060;</span>'; // ❌
    threatLevel.textContent = 'Analysis Error';
    threatLevel.style.color = '#dc3545';
    threatLevel.style.fontWeight = 'bold';
    reputation.textContent = 'Analysis failed - please try again';
    reputation.style.color = '#dc3545';
    updateAlertsSection('error', 'Analysis failed');

  } else {
    threatIcon.innerHTML = '<span style="color: #6c757d; font-size: 16px;">&#10067;</span>'; // ❓
    threatLevel.textContent = 'Unknown';
    threatLevel.style.color = '#6c757d';
    threatLevel.style.fontWeight = 'normal';
    reputation.textContent = 'Analysis pending...';
    reputation.style.color = '#6c757d';
    updateAlertsSection('unknown');
  }
}

// Update alerts section based on threat level
function updateAlertsSection(threatLevel, details = '') {
  const alertsList = document.getElementById('alerts-list');
  if (!alertsList) return;

  // Clear existing alerts
  alertsList.innerHTML = '';

  switch (threatLevel) {
    case 'high':
      alertsList.innerHTML = `
        <div class="alert-item high-risk">
          <span class="alert-icon">🚨</span>
          <div class="alert-content">
            <div class="alert-title">High Risk Detected</div>
            <div class="alert-details">${details || 'Multiple security threats detected'}</div>
            <div class="alert-time">Just now</div>
          </div>
        </div>
      `;
      break;

    case 'medium':
      alertsList.innerHTML = `
        <div class="alert-item medium-risk">
          <span class="alert-icon">⚠️</span>
          <div class="alert-content">
            <div class="alert-title">Medium Risk Detected</div>
            <div class="alert-details">${details || 'Some security concerns detected'}</div>
            <div class="alert-time">Just now</div>
          </div>
        </div>
      `;
      break;

    case 'safe':
      alertsList.innerHTML = `
        <div class="no-alerts" style="animation: scanComplete 0.5s ease-in-out;">
          <span class="no-alerts-icon" style="color: #28a745; font-size: 24px;">&#9989;</span>
          <span class="no-alerts-text" style="color: #28a745; font-weight: bold;">Security Scan Complete</span>
          <span class="no-alerts-subtext" style="color: #6c757d;">No threats detected - Safe to browse</span>
          <div style="margin-top: 8px; font-size: 12px; color: #6c757d;">
            <span>🔒 SSL Certificate: Valid</span><br>
            <span>🛡️ Threat Analysis: Clean</span><br>
            <span>⏱️ Scan Time: ${new Date().toLocaleTimeString()}</span>
          </div>
        </div>
      `;
      break;

    case 'error':
      alertsList.innerHTML = `
        <div class="alert-item error">
          <span class="alert-icon">❌</span>
          <div class="alert-content">
            <div class="alert-title">Analysis Error</div>
            <div class="alert-details">${details || 'Failed to analyze security'}</div>
            <div class="alert-time">Just now</div>
          </div>
        </div>
      `;
      break;

    case 'disabled':
      alertsList.innerHTML = `
        <div class="no-alerts">
          <span class="no-alerts-icon">⏸️</span>
          <span class="no-alerts-text">Extension Disabled</span>
          <span class="no-alerts-subtext">Enable WebShield to monitor threats</span>
        </div>
      `;
      break;

    default:
      alertsList.innerHTML = `
        <div class="no-alerts">
          <span class="no-alerts-icon">❓</span>
          <span class="no-alerts-text">Analysis Pending</span>
          <span class="no-alerts-subtext">Checking security status...</span>
        </div>
      `;
      break;
  }
}

// Show loading state with enhanced progress indication
function showLoadingState() {
  const elements = ['ssl-icon', 'threat-icon'];
  elements.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.innerHTML = '<span style="color: #007bff; font-size: 16px;">&#128270;</span>'; // 🔍
      element.style.animation = 'sslWarning 1s ease-in-out infinite';
    }
  });

  const statusElements = ['ssl-status', 'threat-level'];
  statusElements.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = '🔍 Scanning...';
      element.style.color = '#007bff';
      element.style.fontWeight = 'normal';
    }
  });

  // Update reputation text
  const reputation = document.getElementById('domain-reputation');
  if (reputation) {
    reputation.textContent = 'Security analysis in progress...';
    reputation.style.color = '#007bff';
  }

  // Update alerts section to show scanning status
  const alertsList = document.getElementById('alerts-list');
  if (alertsList) {
    alertsList.innerHTML = `
      <div class="scanning-status" style="text-align: center; padding: 20px; animation: scanComplete 0.5s ease-in-out;">
        <div style="color: #007bff; font-size: 24px; margin-bottom: 10px;">&#128270;</div>
        <div style="color: #007bff; font-weight: bold; margin-bottom: 5px;">Security Scan in Progress</div>
        <div style="color: #6c757d; font-size: 12px;">Analyzing SSL certificate and checking for threats...</div>
        <div style="margin-top: 10px;">
          <div class="progress-bar" style="width: 100%; height: 4px; background: #e9ecef; border-radius: 2px; overflow: hidden;">
            <div class="progress-fill" style="width: 0%; height: 100%; background: linear-gradient(90deg, #007bff, #28a745); animation: progressAnimation 2s ease-in-out infinite;"></div>
          </div>
        </div>
      </div>
    `;
  }

  // Add progress animation
  addProgressAnimation();
}

// Add progress animation to the page
function addProgressAnimation() {
  if (document.getElementById('webshield-progress-animations')) return;

  const style = document.createElement('style');
  style.id = 'webshield-progress-animations';
  style.textContent = `
    @keyframes progressAnimation {
      0% { width: 0%; }
      50% { width: 70%; }
      100% { width: 100%; }
    }
  `;
  document.head.appendChild(style);
}

// Hide loading state with completion feedback
function hideLoadingState() {
  // Clear any loading animations
  const elements = ['ssl-icon', 'threat-icon'];
  elements.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.style.animation = 'none';
    }
  });

  // Show completion notification
  showNotification('Security scan completed successfully!', 'success');

  // Add completion animation to the entire popup
  const popupRoot = document.getElementById('popup-root');
  if (popupRoot) {
    popupRoot.style.animation = 'scanComplete 0.5s ease-in-out';
  }

  // Show scan summary after a short delay
  setTimeout(() => {
    showScanSummary();
  }, 500);
}

// Show scan summary with enhanced details
function showScanSummary() {
  const alertsList = document.getElementById('alerts-list');
  if (!alertsList) return;

  // Get current scan results
  const sslStatus = document.getElementById('ssl-status');
  const threatLevel = document.getElementById('threat-level');
  const reputation = document.getElementById('domain-reputation');

  if (sslStatus && threatLevel && reputation) {
    const sslText = sslStatus.textContent;
    const threatText = threatLevel.textContent;
    const reputationText = reputation.textContent;

    // Create enhanced summary
    let summaryHTML = `
      <div class="scan-summary" style="animation: scanComplete 0.5s ease-in-out;">
        <div style="text-align: center; padding: 15px; background: linear-gradient(135deg, #f8f9fa, #e9ecef); border-radius: 8px; margin: 10px 0;">
          <div style="color: #28a745; font-size: 20px; margin-bottom: 8px;">&#9989;</div>
          <div style="color: #28a745; font-weight: bold; margin-bottom: 5px;">Scan Summary</div>
          <div style="font-size: 12px; color: #6c757d; line-height: 1.4;">
            <div style="margin: 3px 0;">🔒 ${sslText}</div>
            <div style="margin: 3px 0;">🛡️ ${threatText}</div>
            <div style="margin: 3px 0;">📊 ${reputationText}</div>
            <div style="margin: 8px 0; padding-top: 8px; border-top: 1px solid #dee2e6;">
              <span>⏱️ Completed: ${new Date().toLocaleTimeString()}</span>
            </div>
          </div>
        </div>
      </div>
    `;

    // Replace the current alerts with summary
    alertsList.innerHTML = summaryHTML;
  }
}

// Setup all button event listeners
function setupButtonListeners() {
  // Settings button (top left)
  document.getElementById('settings-btn')?.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
  });

  // Refresh button (next to settings)
  document.getElementById('refresh-btn')?.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (url) {
        // Re-analyze current page
        analyzeCurrentPage(url);
        // Clear the report frame
        document.getElementById('report-frame').src = '';
      }
    });
  });

  // Extension toggle button (in protection banner)
  document.getElementById('extension-toggle')?.addEventListener('click', () => {
    chrome.storage.sync.get({ extensionEnabled: true }, (settings) => {
      const newState = !settings.extensionEnabled;

      chrome.storage.sync.set({ extensionEnabled: newState }, () => {
        updateToggleUI(newState);

        // Show notification
        const message = newState ? 'WebShield Enabled' : 'WebShield Disabled';
        showNotification(message, newState ? 'success' : 'warning');

        // Reload current page analysis if enabled
        if (newState) {
          chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const url = tabs[0]?.url;
            if (url) {
              analyzeCurrentPage(url);
            }
          });
        } else {
          showDisabledState();
        }
      });
    });
  });

  // Close report button
  document.getElementById('close-report')?.addEventListener('click', () => {
    document.getElementById('report-section').style.display = 'none';
    document.getElementById('report-frame').src = '';
  });

  // View details button - ALWAYS triggers a fresh scan for accurate real-time data
  document.getElementById('view-details-btn')?.addEventListener('click', async () => {
    console.log('🔍 View Details button clicked - triggering fresh scan');
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      const url = tabs[0]?.url;
      console.log('🔍 Current tab URL:', url);

      if (!url) {
        console.error('WebShield: No active tab URL found');
        showNotification('Failed to get current page URL. Please try again.', 'error');
        return;
      }

      // IMPORTANT: Always perform a fresh scan for accurate real-time data
      // Do NOT use cached/stored scan IDs to ensure the report shows current threat status
      console.log('WebShield: Performing fresh scan for accurate results');
      showNotification('Scanning URL for detailed security analysis...', 'info');

      // Show loading state
      const viewDetailsBtn = document.getElementById('view-details-btn');
      const originalHTML = viewDetailsBtn.innerHTML;
      viewDetailsBtn.innerHTML = '<span class="btn-icon">🔄</span><span class="btn-text">Scanning...</span>';
      viewDetailsBtn.disabled = true;

      try {
        // Request a fresh scan from the background script
        chrome.runtime.sendMessage({ type: 'CHECK_URL', url, forceRescan: true }, async (result) => {
          console.log('WebShield: Fresh scan result:', result);

          if (result && result.scan_id) {
            console.log('WebShield: Fresh scan completed with ID:', result.scan_id);
            // Store the new scan ID
            chrome.storage.local.set({
              lastScanId: result.scan_id,
              lastScanUrl: url,
              lastScanTime: Date.now()
            });

            const webAppBase = await getWebAppBaseURL();
            // Add timestamp to prevent browser caching
            const reportUrl = `${webAppBase}/scan_report.html?scan_id=${result.scan_id}&_t=${Date.now()}`;
            console.log('WebShield: Opening fresh report URL:', reportUrl);
            chrome.tabs.create({ url: reportUrl });
          } else {
            // Fallback: trigger scan on the scan-url page
            console.log('WebShield: No scan_id received, redirecting to scan page');
            const webAppBase = await getWebAppBaseURL();
            chrome.tabs.create({ url: `${webAppBase}/scan-url.html?url=${encodeURIComponent(url)}` });
          }

          // Reset button state
          viewDetailsBtn.innerHTML = originalHTML;
          viewDetailsBtn.disabled = false;
        });
      } catch (error) {
        console.error('WebShield: Error during scan:', error);
        showNotification('Failed to scan URL. Please try again.', 'error');
        // Reset button state
        viewDetailsBtn.innerHTML = originalHTML;
        viewDetailsBtn.disabled = false;
      }
    });
  });

  // Dashboard button
  document.getElementById('dashboard-btn')?.addEventListener('click', async () => {
    const webAppBase = await getWebAppBaseURL();
    chrome.tabs.create({ url: `${webAppBase}/dashboard.html` });
  });

  // Export button - open website's Export page
  document.getElementById('export-btn')?.addEventListener('click', async () => {
    const webAppBase = await getWebAppBaseURL();
    chrome.tabs.create({ url: `${webAppBase}/export.html` });
  });

  // Help button
  document.getElementById('help-btn')?.addEventListener('click', async () => {
    const webAppBase = await getWebAppBaseURL();
    chrome.tabs.create({ url: `${webAppBase}/how-to-install.html` });
  });

  // Retry button (for error overlay)
  document.getElementById('retry-btn')?.addEventListener('click', () => {
    document.getElementById('error-overlay').style.display = 'none';
    // Retry the last operation
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;
      if (url) {
        analyzeCurrentPage(url);
      }
    });
  });

  // Emergency button
  document.getElementById('emergency-btn')?.addEventListener('click', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id) {
        chrome.tabs.remove(tabs[0].id);
      }
    });
  });


}

// Show notification function
function showNotification(message, type = 'info') {
  // Create notification element
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === 'error' ? '#dc3545' : type === 'warning' ? '#ffc107' : type === 'success' ? '#28a745' : '#007bff'};
    color: white;
    padding: 15px 20px;
    border-radius: 5px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    z-index: 999999;
    box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    max-width: 300px;
    word-wrap: break-word;
  `;

  notification.textContent = message;
  document.body.appendChild(notification);

  // Auto-remove after 5 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 5000);
}

// Listen for threat alerts from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('WebShield: Received message in popup:', message.type);

  switch (message.type) {
    case 'SHOW_THREAT_ALERT':
      const threatMessage = `🚨 Threat Detected: ${message.level} risk site`;
      showNotification(threatMessage, 'error');
      break;

    case 'THREAT_ALERT':
      // Update alerts section based on threat level
      updateAlertsSection(message.level, `Threat detected by security analysis`);

      // Show notification with enhanced details
      let alertMessage = `🚨 Threat Detected: ${message.level} risk site`;
      if (message.details) {
        const { malicious_count, total_engines } = message.details;
        if (malicious_count && total_engines) {
          alertMessage += ` (${malicious_count}/${total_engines} engines)`;
        }
      }
      showNotification(alertMessage, 'error');

      // Store scan details for View Details
      if (message.scanId) {
        chrome.storage.local.set({
          lastScanId: message.scanId,
          lastThreatDetails: message.details
        });
      }
      break;

    case 'SCAN_COMPLETED':
      // Handle scan completion notification
      if (message.scanId) {
        chrome.storage.local.set({ lastScanId: message.scanId });
        showNotification('Security scan completed', 'success');
      }
      break;

    case 'API_STATUS':
      // Handle API status updates
      if (message.offlineMode) {
        showNotification('Running in offline mode', 'warning');
      }
      break;
  }
});

