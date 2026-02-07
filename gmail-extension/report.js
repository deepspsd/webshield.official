// WebShield Gmail Report - World-Class Enhanced Version
// Version 2.0.0 - Professional Security Report Generation

// ===== CONSTANTS =====
const SAFE_SCORE_THRESHOLD = 33;
const SUSPICIOUS_SCORE_THRESHOLD = 66;

/**
 * Escapes HTML characters to prevent XSS attacks
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
 * Format timestamp to readable date
 * @param {number} timestamp - Unix timestamp
 * @returns {string} Formatted date string
 */
function formatDate(timestamp) {
  if (!timestamp) return 'N/A';
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Get threat level color class
 * @param {number} score - Threat score
 * @returns {string} CSS color - Matching main extension theme
 */
function getThreatColor(score) {
  if (score <= SAFE_SCORE_THRESHOLD) return '#28a745'; // Success green (--success)
  if (score <= SUSPICIOUS_SCORE_THRESHOLD) return '#ffc107'; // Warning amber (--warning)
  return '#dc3545'; // Danger red (--danger)
}

/**
 * Render authentication status pill
 * @param {string} status - Auth status (pass/fail/unknown/temperror/permerror/none/not_available)
 * @returns {string} HTML string
 */
function renderAuthStatus(status) {
  const s = (status || 'unknown').toLowerCase();

  // Passing statuses
  if (s === 'pass') {
    return '<span class="status-pill pass">PASSED</span>';
  }

  // Failing statuses
  if (s === 'fail' || s === 'permerror') {
    return '<span class="status-pill fail">FAILED</span>';
  }

  // Anything else should be treated as unknown for user-facing semantics.
  // (Examples: none/temperror/unavailable/not_available/neutral)
  return '<span class="status-pill neutral">UNKNOWN</span>';
}

/**
 * Render individual reason with proper icon
 * @param {string} reason - Reason text
 * @returns {string} HTML string
 */
function renderReason(reason) {
  const lowerReason = reason.toLowerCase();
  let icon = '•';
  let className = 'neutral';

  if (lowerReason.includes('✓') || lowerReason.includes('safe') || lowerReason.includes('verified') || lowerReason.includes('passed') || lowerReason.includes('legitimate')) {
    icon = '✓';
    className = 'positive';
  } else if (lowerReason.includes('⚠️') || lowerReason.includes('suspicious') || lowerReason.includes('mismatch') || lowerReason.includes('differ')) {
    icon = '⚠';
    className = 'warning';
  } else if (lowerReason.includes('dangerous') || lowerReason.includes('malicious') || lowerReason.includes('attack') || lowerReason.includes('threat')) {
    icon = '✕';
    className = 'danger';
  }

  // Clean the reason text
  const cleanReason = escapeHTML(reason).replace(/^[✓!⚠️✕•]/g, '').trim();

  return `<li class="reason-item ${className}"><span class="reason-icon">${icon}</span><span>${cleanReason}</span></li>`;
}

/**
 * Render link item with risk assessment
 * @param {Object|string} link - Link object or URL string
 * @param {Object} linkAnalysis - Link analysis data
 * @returns {string} HTML string
 */
function renderLink(link, linkAnalysis) {
  const url = typeof link === 'string' ? link : (link.url || link.href || '');
  const safeUrl = escapeHTML(url);
  const displayUrl = url.length > 60 ? url.substring(0, 57) + '...' : url;

  // Determine link risk
  let riskClass = 'safe';
  let riskLabel = 'Safe';

  const suspiciousLinks = linkAnalysis?.suspicious_links || [];
  const isSuspicious = suspiciousLinks.some(sl => sl.url === url || sl === url);
  const hasTextMismatch = typeof link === 'object' && link.textUrlMismatch;

  const scanResult = (linkAnalysis && linkAnalysis.link_scan_results && url)
    ? linkAnalysis.link_scan_results[url]
    : null;
  const scanVerdict = (scanResult && scanResult.verdict) ? String(scanResult.verdict).toLowerCase() : null;

  if (hasTextMismatch) {
    riskClass = 'danger';
    riskLabel = 'URL Mismatch';
  } else if (scanVerdict === 'malicious') {
    riskClass = 'danger';
    riskLabel = 'Dangerous';
  } else if (scanVerdict === 'suspicious') {
    riskClass = 'warning';
    riskLabel = 'Suspicious';
  } else if (isSuspicious) {
    riskClass = 'warning';
    riskLabel = 'Suspicious';
  }

  return `
        <li class="link-item ${riskClass}">
            <div class="link-url" title="${safeUrl}">${escapeHTML(displayUrl)}</div>
            <span class="link-risk ${riskClass}">${riskLabel}</span>
        </li>`;
}

/**
 * Generate the threat score ring SVG
 * @param {number} score - Threat score (0-100)
 * @returns {string} SVG HTML string
 */
function renderThreatRing(score) {
  const color = getThreatColor(score);
  const circumference = 2 * Math.PI * 45; // radius = 45
  const progress = (score / 100) * circumference;

  return `
        <svg class="threat-ring" viewBox="0 0 100 100">
            <circle class="ring-bg" cx="50" cy="50" r="45"/>
            <circle class="ring-progress" cx="50" cy="50" r="45" 
                stroke="${color}" 
                stroke-dasharray="${progress} ${circumference}"
                transform="rotate(-90 50 50)"/>
            <text x="50" y="50" class="ring-score">${score}</text>
            <text x="50" y="64" class="ring-label">/ 100</text>
        </svg>`;
}

/**
 * Main render function for the security report
 * @param {Object} scanResult - Scan result data
 * @returns {string} Complete HTML report
 */
function renderReport(scanResult) {
  const level = (scanResult?.threat_level || 'unknown').toLowerCase();
  const summary = escapeHTML(scanResult?.summary || 'Analysis complete');
  const score = scanResult?.threat_score || 0;

  // Default reasons if empty
  const reasons = scanResult?.reasons && scanResult.reasons.length
    ? scanResult.reasons
    : ['✓ Sender reputation analyzed', '✓ Link structure verified', '✓ Content patterns checked'];

  // Extract detailed data
  const senderRep = scanResult?.details?.sender_reputation || {};
  const repScore = senderRep.reputation_score ?? 0;
  const senderDomain = escapeHTML(senderRep.domain || 'Unknown');

  const auth = scanResult?.details?.header_analysis || {};
  const links = scanResult?.details?.link_analysis?.links || scanResult?.links || [];
  const linkAnalysis = scanResult?.details?.link_analysis || {};
  const contentAnalysis = scanResult?.details?.content_analysis || {};

  const authPostureParts = [];
  if (auth.spf_posture) authPostureParts.push(`SPF: ${escapeHTML(String(auth.spf_posture))}`);
  if (auth.dkim_posture) authPostureParts.push(`DKIM: ${escapeHTML(String(auth.dkim_posture))}`);
  if (auth.dmarc_posture) authPostureParts.push(`DMARC: ${escapeHTML(String(auth.dmarc_posture))}`);
  const authPostureText = authPostureParts.length ? authPostureParts.join(' | ') : 'Unknown';

  const isOffline = scanResult?.is_offline_analysis || false;
  const scannedAt = scanResult?.timestamp || Date.now();

  const isTrustedDomain = !!senderRep.is_trusted_domain;
  const verifiedText = isTrustedDomain && !isOffline
    ? '✅ Verified'
    : (isTrustedDomain ? '➖ Trusted (offline)' : '❌ Not verified');

  // Determine severity
  let severity = 'safe';
  let icon = '🛡️';
  let title = 'Email is Safe';
  let titleClass = 'safe';

  if (level.includes('danger') || level.includes('malicious') || score > SUSPICIOUS_SCORE_THRESHOLD) {
    severity = 'danger';
    icon = '⛔';
    title = 'Dangerous Email Detected';
    titleClass = 'danger';
  } else if (level.includes('suspicious') || level.includes('medium') || score > SAFE_SCORE_THRESHOLD) {
    severity = 'warning';
    icon = '⚠️';
    title = 'Suspicious Email';
    titleClass = 'warning';
  }

  // Copy badge button (only for safe emails)
  const copyBadgeHTML = severity === 'safe'
    ? `<button id="copy-badge-btn" class="copy-btn">📋 Copy Security Badge</button>`
    : '';

  // Generate reasons HTML
  const reasonsHTML = reasons.slice(0, 6).map(renderReason).join('');

  // Generate links HTML
  const linksHTML = links.length === 0
    ? '<div class="empty-state">No links found in this email</div>'
    : `<ul class="links-list">${links.map(l => renderLink(l, linkAnalysis)).join('')}</ul>`;

  // Suspicious links count
  const suspiciousLinkCount = linkAnalysis.suspicious_links?.length || 0;

  // Phishing keywords count
  const phishingKeywords = contentAnalysis.phishing_keywords_found || 0;

  return `
        <!-- Premium Header -->
        <header class="report-header ${titleClass}">
            <div class="header-content">
                <div class="header-icon">${icon}</div>
                <div class="header-info">
                    <h1 class="header-title">${title}</h1>
                    <p class="header-summary">${summary}</p>
                </div>
            </div>
            ${renderThreatRing(score)}
        </header>

        <!-- Analysis Badges -->
        <div class="badges-row">
            ${isOffline ? '<span class="badge offline">⚡ Offline Analysis</span>' : '<span class="badge online">🌐 Live Analysis</span>'}
            <span class="badge timestamp">🕐 ${formatDate(scannedAt)}</span>
        </div>

        <div class="report-body">
            <!-- Key Findings Section -->
            <section class="report-section findings">
                <h2 class="section-title">Key Findings</h2>
                <ul class="reasons-list">
                    ${reasonsHTML}
                </ul>
                ${copyBadgeHTML}
            </section>

            <!-- Statistics Grid -->
            <section class="report-section">
                <h2 class="section-title">Security Analysis</h2>
                <div class="stats-grid">
                    <div class="stat-card ${repScore >= 70 ? 'good' : repScore >= 40 ? 'warning' : 'bad'}">
                        <div class="stat-icon">📊</div>
                        <div class="stat-value">${repScore}</div>
                        <div class="stat-label">Reputation Score</div>
                    </div>
                    <div class="stat-card ${senderRep.is_trusted_domain ? 'good' : 'neutral'}">
                        <div class="stat-icon">${senderRep.is_trusted_domain ? '✅' : '❓'}</div>
                        <div class="stat-value">${senderRep.is_trusted_domain ? 'Yes' : 'No'}</div>
                        <div class="stat-label">Trusted Domain</div>
                    </div>
                    <div class="stat-card ${links.length > 10 ? 'warning' : 'neutral'}">
                        <div class="stat-icon">🔗</div>
                        <div class="stat-value">${links.length}</div>
                        <div class="stat-label">Links Found</div>
                    </div>
                    <div class="stat-card ${suspiciousLinkCount > 0 ? 'bad' : 'good'}">
                        <div class="stat-icon">${suspiciousLinkCount > 0 ? '⚠️' : '✅'}</div>
                        <div class="stat-value">${suspiciousLinkCount}</div>
                        <div class="stat-label">Suspicious Links</div>
                    </div>
                </div>
            </section>

            <!-- Sender Information -->
            <section class="report-section">
                <h2 class="section-title">Sender Information</h2>
                <div class="info-table">
                    <div class="info-row">
                        <span class="info-label">Domain</span>
                        <span class="info-value">${senderDomain}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Verified</span>
                        <span class="info-value">${verifiedText}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Authenticated</span>
                        <span class="info-value">${auth.is_authenticated ? '✅ Yes' : '❌ No'}</span>
                    </div>
                </div>
            </section>

            <!-- Authentication Checks -->
            <section class="report-section">
                <h2 class="section-title">Email Authentication</h2>
                <div class="info-table" style="margin-bottom: 12px;">
                    <div class="info-row">
                        <span class="info-label">Domain posture (DNS)</span>
                        <span class="info-value">${authPostureText}</span>
                    </div>
                </div>
                <div class="auth-grid">
                    <div class="auth-item">
                        <span class="auth-label">SPF</span>
                        ${renderAuthStatus(auth.spf_status)}
                    </div>
                    <div class="auth-item">
                        <span class="auth-label">DKIM</span>
                        ${renderAuthStatus(auth.dkim_status)}
                    </div>
                    <div class="auth-item">
                        <span class="auth-label">DMARC</span>
                        ${renderAuthStatus(auth.dmarc_status)}
                    </div>
                </div>
            </section>

            <!-- Content Analysis -->
            ${phishingKeywords > 0 ? `
            <section class="report-section warning-section">
                <h2 class="section-title">⚠️ Content Warnings</h2>
                <div class="warning-content">
                    <p><strong>${phishingKeywords}</strong> phishing keyword(s) detected in email content</p>
                    ${contentAnalysis.detected_keywords?.length > 0 ? `
                        <div class="keywords-detected">
                            ${contentAnalysis.detected_keywords.slice(0, 5).map(k =>
    `<span class="keyword-tag">${escapeHTML(k.keyword || k)}</span>`
  ).join('')}
                        </div>
                    ` : ''}
                </div>
            </section>
            ` : ''}

            <!-- Links Section -->
            <section class="report-section">
                <h2 class="section-title">Links Analysis</h2>
                ${linksHTML}
            </section>

            <!-- Footer -->
            <footer class="report-footer">
                <div class="footer-brand">
                    <span class="footer-icon">🛡️</span>
                    <span>WebShield Gmail Scanner v2.0.0</span>
                </div>
                <div class="footer-actions">
                    <button id="rescan-btn" class="action-btn">🔄 Re-scan</button>
                    <button id="export-btn" class="action-btn">📥 Export Report</button>
                </div>
            </footer>
        </div>
    `;
}

/**
 * Export report as text
 * @param {Object} scanResult - Scan result data
 * @returns {string} Text report
 */
function exportReport(scanResult) {
  const score = scanResult?.threat_score || 0;
  const level = scanResult?.threat_level || 'Unknown';
  const summary = scanResult?.summary || '';
  const reasons = scanResult?.reasons || [];
  const senderRep = scanResult?.details?.sender_reputation || {};
  const auth = scanResult?.details?.header_analysis || {};

  return `
WebShield Security Report
========================
Generated: ${formatDate(Date.now())}

THREAT ASSESSMENT
-----------------
Score: ${score}/100
Level: ${level.toUpperCase()}
Summary: ${summary}

KEY FINDINGS
------------
${reasons.map(r => `• ${r}`).join('\n')}

SENDER INFORMATION
------------------
Domain: ${senderRep.domain || 'Unknown'}
Reputation Score: ${senderRep.reputation_score || 'N/A'}/100
Trusted Domain: ${senderRep.is_trusted_domain ? 'Yes' : 'No'}

AUTHENTICATION
--------------
SPF: ${auth.spf_status || 'Unknown'}
DKIM: ${auth.dkim_status || 'Unknown'}
DMARC: ${auth.dmarc_status || 'Unknown'}
Encrypted: ${auth.encrypted ? 'Yes' : 'No'}

---
Report generated by WebShield Gmail Scanner v2.0.0
    `.trim();
}

// ===== DOM Ready Handler =====
document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const threadId = params.get('id');
  const load = document.getElementById('loading');
  const root = document.getElementById('report-root');
  let currentScanData = null;

  function findGmailTabForThread(threadId, callback) {
    chrome.tabs.query({ url: '*://mail.google.com/*' }, (tabs) => {
      const t = (tabs || []).find(tb => {
        const u = tb?.url || '';
        return u.includes(threadId) || new RegExp(`\\/(${threadId})$`).test(u);
      }) || (tabs?.[0] || null);
      callback(t);
    });
  }

  if (!threadId) {
    load.innerHTML = `
            <div class="error-state">
                <span class="error-icon">❌</span>
                <p>Error: No email ID provided</p>
                <button onclick="window.close()" class="close-btn">Close</button>
            </div>`;
    return;
  }

  const key = 'gmail_report_' + threadId;
  chrome.storage.local.get([key, 'webshield_gmail_last_scan'], (result) => {
    if (chrome.runtime.lastError) {
      load.innerHTML = `
                <div class="error-state">
                    <span class="error-icon">⚠️</span>
                    <p>Failed to load report: ${escapeHTML(chrome.runtime.lastError.message)}</p>
                </div>`;
      return;
    }

    let data = result[key];

    // Fallback to last scan if specific thread not found
    if (!data && result.webshield_gmail_last_scan) {
      data = result.webshield_gmail_last_scan;
    }

    if (!data || !data.scanResult) {
      // No report found - show scan prompt
      load.innerHTML = `
                <div class="no-report-state">
                    <span class="state-icon">📧</span>
                    <h2>No Report Found</h2>
                    <p>This email hasn't been scanned yet</p>
                    <button id="report-scan-btn" class="primary-btn">🔍 Scan Now</button>
                </div>`;

      document.getElementById('report-scan-btn')?.addEventListener('click', () => {
        load.innerHTML = `
                    <div class="scanning-state">
                        <div class="spinner"></div>
                        <p>Scanning email...</p>
                    </div>`;

        findGmailTabForThread(threadId, (target) => {
          if (target) {
            chrome.tabs.sendMessage(target.id, { type: 'GMAIL_EXT_SCAN_EMAIL_MANUAL' }, (resp) => {
              if (chrome.runtime.lastError) {
                load.innerHTML = `
                                    <div class="error-state">
                                        <span class="error-icon">⚠️</span>
                                        <p>Connection failed. Please refresh Gmail and try again.</p>
                                    </div>`;
                return;
              }

              if (resp?.success) {
                setTimeout(() => window.location.reload(), 1500);
              } else {
                load.innerHTML = `
                                    <div class="error-state">
                                        <span class="error-icon">❌</span>
                                        <p>Scan failed: ${escapeHTML(resp?.error || 'Unknown error')}</p>
                                    </div>`;
              }
            });
          } else {
            load.innerHTML = `
                            <div class="error-state">
                                <span class="error-icon">📭</span>
                                <p>Gmail tab not found. Please open Gmail first.</p>
                            </div>`;
          }
        });
      });
      return;
    }

    // Store for actions
    currentScanData = data;

    // Hide loading, show report
    load.classList.add('hidden');
    root.innerHTML = renderReport(data.scanResult);
    root.classList.remove('hidden');

    // Wire up copy badge button
    document.getElementById('copy-badge-btn')?.addEventListener('click', () => {
      const score = data.scanResult.threat_score || 0;
      const text = `✅ Verified safe by WebShield – Threat Score: ${score}/100`;
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('copy-badge-btn');
        btn.textContent = '✓ Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = '📋 Copy Security Badge';
          btn.classList.remove('copied');
        }, 2000);
      });
    });

    // Wire up rescan button
    document.getElementById('rescan-btn')?.addEventListener('click', () => {
      findGmailTabForThread(threadId, (target) => {
        if (target) {
          const btn = document.getElementById('rescan-btn');
          btn.textContent = '⏳ Scanning...';
          btn.disabled = true;

          chrome.tabs.sendMessage(target.id, { type: 'GMAIL_EXT_SCAN_EMAIL_MANUAL' }, (resp) => {
            if (resp?.success) {
              setTimeout(() => window.location.reload(), 1500);
            } else {
              btn.textContent = '❌ Failed';
              setTimeout(() => {
                btn.textContent = '🔄 Re-scan';
                btn.disabled = false;
              }, 2000);
            }
          });
        }
      });
    });

    // Wire up export button
    document.getElementById('export-btn')?.addEventListener('click', () => {
      const reportText = exportReport(data.scanResult);
      const blob = new Blob([reportText], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `webshield-report-${threadId.substring(0, 8)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
    });
  });
});
