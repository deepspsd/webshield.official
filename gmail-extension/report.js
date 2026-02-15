// WebShield Gmail Report - World-Class Enhanced Version
// Version 2.2.0 - Professional Security Report Generation

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

  const suspiciousLinks = Array.isArray(linkAnalysis?.suspicious_links) ? linkAnalysis.suspicious_links : [];
  const isSuspicious = suspiciousLinks.some(sl => {
    if (!sl) return false;
    if (typeof sl === 'string') return sl === url;
    if (typeof sl === 'object') return sl.url === url || sl.href === url;
    return false;
  });
  const hasTextMismatch = (typeof link === 'object' && !!link.textUrlMismatch)
    || suspiciousLinks.some(sl => (sl && typeof sl === 'object' && (sl.url === url || sl.href === url) && !!sl.textUrlMismatch));

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
  const linkAnalysis = scanResult?.details?.link_analysis || {};
  const links = Array.isArray(scanResult?.link_details) && scanResult.link_details.length
    ? scanResult.link_details
    : (scanResult?.details?.link_analysis?.links || scanResult?.links || []);
  const contentAnalysis = scanResult?.details?.content_analysis || {};
  const attachments = scanResult?.details?.attachments || scanResult?.attachments || [];
  const hasDangerousAttachments = !!(scanResult?.details?.has_dangerous_attachments || scanResult?.has_dangerous_attachments);

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
  const suspiciousLinkCount = Array.isArray(linkAnalysis.suspicious_links) ? linkAnalysis.suspicious_links.length : 0;

  // Phishing keywords count
  const phishingKeywords = contentAnalysis.phishing_keywords_found || 0;

  const redirectChains = linkAnalysis.redirect_chains || {};
  const redirectUrls = Object.keys(redirectChains || {});



  const linkScanResults = linkAnalysis.link_scan_results || {};
  const linkScanUrls = Object.keys(linkScanResults || {});

  const receivedHeaders = Array.isArray(auth.received) ? auth.received : (Array.isArray(scanResult?.headers?.received) ? scanResult.headers.received : []);
  const replyToHeader = auth.reply_to || scanResult?.headers?.reply_to || '';
  const returnPathHeader = auth.return_path || scanResult?.headers?.return_path || '';

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
            ${scanResult?.confidence ? `<span class="badge" style="background:rgba(0,188,212,0.15);color:#00bcd4;border-color:rgba(0,188,212,0.3)">🎯 ${Math.round(scanResult.confidence * 100)}% Confidence</span>` : ''}
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
                    ${senderRep.domain_age_days !== null && senderRep.domain_age_days !== undefined ? `
                    <div class="info-row">
                        <span class="info-label">Domain Age</span>
                        <span class="info-value" style="${senderRep.is_newly_registered ? 'color:#dc3545;font-weight:600' : ''}">
                          ${senderRep.is_newly_registered ? '⚠️ ' : ''}${senderRep.domain_age_days > 365 ? Math.round(senderRep.domain_age_days / 365) + ' years' : senderRep.domain_age_days + ' days'}
                          ${senderRep.domain_created ? ` (since ${escapeHTML(senderRep.domain_created)})` : ''}
                        </span>
                    </div>` : ''}
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
                    ${replyToHeader ? `
                    <div class="info-row">
                        <span class="info-label">Reply-To</span>
                        <span class="info-value">${escapeHTML(replyToHeader)}</span>
                    </div>` : ''}
                    ${returnPathHeader ? `
                    <div class="info-row">
                        <span class="info-label">Return-Path</span>
                        <span class="info-value">${escapeHTML(returnPathHeader)}</span>
                    </div>` : ''}
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
                ${receivedHeaders && receivedHeaders.length > 0 ? `
                <div style="margin-top:12px">
                    <div style="font-size:11px;text-transform:uppercase;font-weight:600;color:#9aa0a6;margin-bottom:6px">Received Headers (${receivedHeaders.length})</div>
                    <div style="max-height:140px;overflow:auto;border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:10px;background:rgba(255,255,255,0.02);font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;font-size:11px;line-height:1.5;color:#b0b8c1">
                        ${receivedHeaders.slice(0, 5).map(h => `<div style="margin-bottom:8px">${escapeHTML(String(h))}</div>`).join('')}
                        ${receivedHeaders.length > 5 ? `<div style="color:#9aa0a6">+ ${receivedHeaders.length - 5} more…</div>` : ''}
                    </div>
                </div>` : ''}
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

            <!-- NLP Phishing Analysis -->
            ${contentAnalysis.nlp_score > 20 ? `
            <section class="report-section" style="border-left: 3px solid ${contentAnalysis.nlp_score > 60 ? '#dc3545' : '#ffc107'}">
                <h2 class="section-title">🧠 NLP Phishing Analysis</h2>
                <div class="info-table">
                    <div class="info-row">
                        <span class="info-label">NLP Risk Score</span>
                        <span class="info-value" style="font-weight:700;color:${contentAnalysis.nlp_score > 60 ? '#dc3545' : contentAnalysis.nlp_score > 30 ? '#ffc107' : '#28a745'}">${contentAnalysis.nlp_score}/100</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Confidence</span>
                        <span class="info-value">${Math.round((contentAnalysis.nlp_confidence || 0) * 100)}%</span>
                    </div>
                </div>
                ${Array.isArray(contentAnalysis.nlp_patterns) && contentAnalysis.nlp_patterns.length > 0 ? `
                <div style="margin-top:8px">
                    ${contentAnalysis.nlp_patterns.slice(0, 5).map(p => `
                    <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 8px;margin:4px 0;background:rgba(255,255,255,0.03);border-radius:6px">
                        <span style="font-size:13px">${escapeHTML(p.pattern_name || p.pattern || 'Pattern')}</span>
                        <span class="keyword-tag" style="font-size:10px">${Math.round((p.score || p.confidence || 0) * 100)}%</span>
                    </div>`).join('')}
                </div>` : ''}
            </section>` : ''}

            <!-- Google Safe Browsing Results -->
            ${(() => {
      const sb = linkAnalysis.safe_browsing_threats || {};
      const sbUrls = Object.keys(sb);
      if (sbUrls.length === 0) return '';
      return `
            <section class="report-section warning-section" style="border-left:3px solid #dc3545">
                <h2 class="section-title">🛡️ Google Safe Browsing Alerts</h2>
                <div class="warning-content">
                    <p><strong>${sbUrls.length}</strong> URL(s) flagged by Google Safe Browsing</p>
                    <ul class="links-list">
                    ${sbUrls.slice(0, 5).map(u => {
        const threats = sb[u] || [];
        return `<li class="link-item danger">
                        <div class="link-url" title="${escapeHTML(u)}">${escapeHTML(u.length > 50 ? u.substring(0, 47) + '...' : u)}</div>
                        <span class="link-risk danger">${escapeHTML(threats.join(', '))}</span>
                      </li>`;
      }).join('')}
                    </ul>
                </div>
            </section>`;
    })()}



            <!-- Redirect Resolution -->
            ${redirectUrls.length > 0 ? `
            <section class="report-section" style="border-left:3px solid #ffc107">
                <h2 class="section-title">↪️ URL Redirect Resolution</h2>
                <div class="warning-content">
                    <p><strong>${redirectUrls.length}</strong> URL(s) resolved through redirects</p>
                </div>
                <div style="margin-top:10px">
                    ${redirectUrls.slice(0, 5).map(u => {
      const chain = Array.isArray(redirectChains[u]) ? redirectChains[u] : [];
      const pretty = [u, ...chain].filter(Boolean);
      return `
                        <div style="margin:10px 0;padding:10px;border:1px solid rgba(255,255,255,0.08);border-radius:10px;background:rgba(255,255,255,0.02)">
                          <div style="font-size:12px;color:#9aa0a6;margin-bottom:6px">Original</div>
                          <div style="font-size:13px;color:#d4d8dc;word-break:break-all">${escapeHTML(u)}</div>
                          ${pretty.length > 1 ? `
                          <div style="font-size:12px;color:#9aa0a6;margin:8px 0 6px">Chain</div>
                          <div style="font-size:12px;color:#b0b8c1;word-break:break-all;line-height:1.6">
                            ${pretty.slice(1, 6).map(step => `<div>→ ${escapeHTML(step)}</div>`).join('')}
                            ${pretty.length > 6 ? `<div style="color:#9aa0a6">+ ${pretty.length - 6} more…</div>` : ''}
                          </div>` : ''}
                        </div>`;
    }).join('')}
                </div>
            </section>` : ''}

            <!-- URL Pattern Analysis -->
            ${linkScanUrls.length > 0 ? `
            <section class="report-section" style="border-left:3px solid #00bcd4">
                <h2 class="section-title">🔎 URL Pattern Analysis</h2>
                <div class="warning-content">
                    <p>ML/rule-based inspection of URL structure (homograph, typosquatting, punycode, suspicious patterns)</p>
                </div>
                <div style="margin-top:10px">
                    ${linkScanUrls.slice(0, 8).map(u => {
      const r = linkScanResults[u] || {};
      const s = Number(r.suspicious_score || 0);
      const issues = Array.isArray(r.detected_issues) ? r.detected_issues : [];
      const badgeColor = s >= 60 ? '#dc3545' : s >= 30 ? '#ffc107' : '#28a745';
      return `
                        <div style="margin:10px 0;padding:10px;border:1px solid rgba(255,255,255,0.08);border-radius:10px;background:rgba(255,255,255,0.02)">
                          <div style="display:flex;justify-content:space-between;gap:10px;align-items:flex-start">
                            <div style="flex:1;min-width:0">
                              <div style="font-size:13px;color:#d4d8dc;word-break:break-all">${escapeHTML(u)}</div>
                              ${issues.length ? `<div style="margin-top:6px;font-size:12px;color:#b0b8c1;line-height:1.5">${issues.slice(0, 4).map(i => `• ${escapeHTML(String(i))}`).join('<br/>')}${issues.length > 4 ? '<br/>…' : ''}</div>` : `<div style="margin-top:6px;font-size:12px;color:#9aa0a6">No issues detected</div>`}
                            </div>
                            <div style="flex-shrink:0">
                              <span class="keyword-tag" style="border-color:${badgeColor};color:${badgeColor};background:rgba(0,0,0,0.15)">${Math.round(s)}/100</span>
                            </div>
                          </div>
                        </div>`;
    }).join('')}
                </div>
            </section>` : ''}

            <!-- Attachment Analysis -->
            ${(attachments && attachments.length > 0) ? `
            <section class="report-section" style="border-left:3px solid ${hasDangerousAttachments ? '#dc3545' : '#28a745'}">
                <h2 class="section-title">📎 Attachment Analysis</h2>
                <div class="warning-content">
                    <p><strong>${attachments.length}</strong> attachment(s) detected${hasDangerousAttachments ? ' — dangerous type(s) present' : ''}</p>
                </div>
                <div style="margin-top:10px">
                    <ul class="links-list">
                        ${attachments.slice(0, 10).map(a => {
      const name = (a && (a.name || a.filename)) ? String(a.name || a.filename) : 'attachment';
      const ext = (a && a.extension) ? String(a.extension) : (name.includes('.') ? name.split('.').pop() : '');
      const vtVerdict = a && a.vt_verdict ? String(a.vt_verdict).toLowerCase() : null;
      const vt = (a && a.vt && typeof a.vt === 'object') ? a.vt : null;
      const vtLabel = vtVerdict === 'malicious'
        ? `VT: Malicious (${vt?.malicious_count ?? 0})`
        : (vtVerdict === 'suspicious'
          ? `VT: Suspicious (${vt?.suspicious_count ?? 0})`
          : (vtVerdict === 'clean' ? 'VT: Clean' : null));
      const vtClass = vtVerdict === 'malicious' ? 'danger' : (vtVerdict === 'suspicious' ? 'warning' : (vtVerdict === 'clean' ? 'safe' : null));
      const isDanger = !!a.is_dangerous || !!a.dangerous || (!!ext && ['exe', 'bat', 'cmd', 'scr', 'js', 'vbs', 'ps1', 'msi', 'dll', 'pif', 'application', 'gadget', 'msc', 'hta', 'cpl', 'msp', 'com', 'jar', 'wsf', 'wsh', 'reg', 'lnk', 'inf', 'scf'].includes(String(ext).toLowerCase()));
      const riskClass = vtClass || (isDanger ? 'danger' : 'safe');
      const riskLabel = vtLabel || (isDanger ? 'Dangerous' : 'File');
      return `<li class="link-item ${riskClass}"><div class="link-url" title="${escapeHTML(name)}">${escapeHTML(name.length > 60 ? name.substring(0, 57) + '...' : name)}</div><span class="link-risk ${riskClass}">${escapeHTML(riskLabel)}</span></li>`;
    }).join('')}
                    </ul>
                </div>
            </section>` : ''}

            <!-- AI Threat Explanation -->
            ${scanResult?.ai_explanation?.why_marked ? `
            <section class="report-section" style="border-left:3px solid #00bcd4">
                <h2 class="section-title">🤖 AI Threat Explanation</h2>
                <div style="font-size:14px;line-height:1.7;color:#d4d8dc;padding:4px 0">
                    ${escapeHTML(scanResult.ai_explanation.why_marked)}
                </div>
                ${Array.isArray(scanResult.ai_explanation.factor_breakdown) && scanResult.ai_explanation.factor_breakdown.length > 0 ? `
                <div style="margin-top:10px">
                    <div style="font-size:11px;text-transform:uppercase;font-weight:600;color:#9aa0a6;margin-bottom:6px">Factor Breakdown</div>
                    <div style="display:flex;flex-wrap:wrap;gap:6px">
                        ${scanResult.ai_explanation.factor_breakdown.map(f => `<span class="keyword-tag" style="background:rgba(220,53,69,0.15);color:#dc3545;border-color:rgba(220,53,69,0.3)">${escapeHTML(f.factor || f.name || JSON.stringify(f))}</span>`).join('')}
                    </div>
                </div>` : ''}
                ${scanResult.ai_explanation.confidence_explanation ? `
                <div style="margin-top:10px">
                    <div style="font-size:11px;text-transform:uppercase;font-weight:600;color:#9aa0a6;margin-bottom:6px">Confidence</div>
                    <div style="font-size:13px;color:#b0b8c1">${escapeHTML(scanResult.ai_explanation.confidence_explanation)}</div>
                </div>` : ''}
                ${scanResult.ai_explanation.recommendations?.length > 0 ? `
                <div style="margin-top:10px">
                    <div style="font-size:11px;text-transform:uppercase;font-weight:600;color:#9aa0a6;margin-bottom:6px">Recommendations</div>
                    <ul style="margin:0;padding-left:16px">
                        ${scanResult.ai_explanation.recommendations.map(r => `<li style="font-size:13px;color:#b0b8c1;margin:4px 0">${escapeHTML(r)}</li>`).join('')}
                    </ul>
                </div>` : ''}
            </section>` : ''}

            <!-- Links Section -->
            <section class="report-section">
                <h2 class="section-title">Links Analysis</h2>
                ${linksHTML}
            </section>

            <!-- Footer -->
            <footer class="report-footer">
                <div class="footer-brand">
                    <span class="footer-icon">🛡️</span>
                    <span>WebShield Gmail Scanner v2.2.0</span>
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
Confidence: ${scanResult?.confidence ? Math.round(scanResult.confidence * 100) + '%' : 'N/A'}
Summary: ${summary}

KEY FINDINGS
------------
${reasons.map(r => `• ${r}`).join('\n')}

SENDER INFORMATION
------------------
Domain: ${senderRep.domain || 'Unknown'}
Reputation Score: ${senderRep.reputation_score || 'N/A'}/100
Trusted Domain: ${senderRep.is_trusted_domain ? 'Yes' : 'No'}
Domain Age: ${senderRep.domain_age_days != null ? senderRep.domain_age_days + ' days' : 'N/A'}
Newly Registered: ${senderRep.is_newly_registered ? 'YES ⚠️' : 'No'}

AUTHENTICATION
--------------
SPF: ${auth.spf_status || 'Unknown'}
DKIM: ${auth.dkim_status || 'Unknown'}
DMARC: ${auth.dmarc_status || 'Unknown'}
Encrypted: ${auth.encrypted ? 'Yes' : 'No'}
${scanResult?.ai_explanation?.why_marked ? `
AI EXPLANATION
--------------
${scanResult.ai_explanation.why_marked}
${scanResult.ai_explanation.factor_breakdown?.length ? '\nFactor Breakdown: ' + scanResult.ai_explanation.factor_breakdown.map(f => f.factor || f.name || JSON.stringify(f)).join(', ') : ''}
${scanResult.ai_explanation.recommendations?.length ? '\nRecommendations:\n' + scanResult.ai_explanation.recommendations.map(r => `  • ${r}`).join('\n') : ''}
` : ''}
---
Report generated by WebShield Gmail Scanner v2.2.0
    `.trim();
}

// ===== DOM Ready Handler =====
document.addEventListener('DOMContentLoaded', () => {
  chrome.storage.sync.get({ dark_mode: false }, (settings) => {
    if (chrome.runtime.lastError) return;
    document.body.classList.toggle('dark-mode', !!settings.dark_mode);
  });

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

    try {
      if (data && data.scanResult) {
        const sr = data.scanResult;
        if (!sr.timestamp) {
          if (data.timestamp) {
            sr.timestamp = data.timestamp;
          } else if (sr.scanned_at) {
            const parsed = Date.parse(sr.scanned_at);
            sr.timestamp = Number.isNaN(parsed) ? Date.now() : parsed;
          }
        }
        if (!sr.scanned_at && sr.timestamp) {
          sr.scanned_at = new Date(sr.timestamp).toISOString();
        }
      }
    } catch (_) {
      // ignore
    }

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
