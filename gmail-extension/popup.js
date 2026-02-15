/**
 * WebShield Gmail Shield Popup Script
 * Enhanced Version 2.1.0
 * World-Class Phishing Detection & Email Security
 * 
 * This script handles the popup UI interactions, displaying scan results,
 * and communicating with the content script for email analysis.
 */

const els = {
  scanBtn: document.getElementById('gr-scan-btn'),
  status: document.getElementById('gr-status'),
  hint: document.getElementById('gr-hint'),
  resultArea: document.getElementById('gr-result-area'),
  threatBadge: document.getElementById('gr-threat-badge'),
  score: document.getElementById('gr-score'),
  summary: document.getElementById('gr-summary'),
  aiContainer: document.getElementById('gr-ai-container'),
  aiWhy: document.getElementById('gr-ai-why'),
  aiRecos: document.getElementById('gr-ai-recos'),
  repScore: document.getElementById('gr-rep-score'),
  linkCount: document.getElementById('gr-link-count'),
  trusted: document.getElementById('gr-trusted'),
  auth: document.getElementById('gr-auth'),
  susLinks: document.getElementById('gr-sus-links'),
  reportBtn: document.getElementById('gr-report-btn'),
  settingsBtn: document.getElementById('gr-settings-btn'),
  toggleTips: document.getElementById('gr-toggle-tips'),
  extendedTips: document.getElementById('gr-extended-tips'),
  // New enhanced elements
  reasonsContainer: document.getElementById('gr-reasons-container'),
  reasonsList: document.getElementById('gr-reasons'),
  offlineBadge: document.getElementById('gr-offline-badge'),
  urlMismatchRow: document.getElementById('gr-url-mismatch-row'),
  urlMismatches: document.getElementById('gr-url-mismatches'),
  keywordsRow: document.getElementById('gr-keywords-row'),
  phishingKeywords: document.getElementById('gr-phishing-keywords'),
  reportPhishing: document.getElementById('gr-report-phishing'),
  markSpam: document.getElementById('gr-mark-spam'),
  showDetails: document.getElementById('gr-show-details')
};

// Message types
const MSG = {
  manualScan: 'GMAIL_EXT_SCAN_EMAIL_MANUAL',
  safetyAction: 'GMAIL_EXT_SAFETY_ACTION'
};

let activeThreadId = null;

function applyThemeFromSettings() {
  chrome.storage.sync.get({ dark_mode: false }, (settings) => {
    if (chrome.runtime.lastError) return;
    document.body.classList.toggle('dark-mode', !!settings.dark_mode);
  });
}

// Initialize the popup
function init() {
  applyThemeFromSettings();

  // Check active tab for Gmail email
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    const isGmail = tab?.url?.includes('mail.google.com');
    const match = tab?.url?.match(/\/([A-Za-z0-9_-]+)$/);
    const threadId = (match && match[1].length > 5) ? match[1] : null;

    if (!isGmail) {
      updateStatus('Not in Gmail', 'offline');
      els.hint.textContent = 'Open Gmail to use this extension';
      els.scanBtn.disabled = true;
      return;
    }

    if (!threadId) {
      updateStatus('Ready', 'ok');
      els.hint.textContent = 'Open an email to scan it';
      els.scanBtn.disabled = true;
      return;
    }

    // Email is open, enable scanning
    updateStatus('Ready', 'ok');
    els.hint.textContent = 'Click to analyze this email for threats';
    els.scanBtn.disabled = false;

    // Check for cached result
    chrome.storage.local.get(['webshield_gmail_last_scan'], (res) => {
      const lastScan = res.webshield_gmail_last_scan;
      if (lastScan && lastScan.emailId === threadId) {
        renderResult(lastScan);
      }
    });
  });
}

function updateStatus(text, type = 'ok') {
  els.status.textContent = text;
  els.status.className = 'status ' + type;
}

// Scan button click handler
els.scanBtn.addEventListener('click', () => {
  els.scanBtn.innerHTML = '<span class="spinner" style="width:14px;height:14px;display:inline-block;vertical-align:middle;margin-right:6px;"></span> Scanning...';
  els.scanBtn.disabled = true;
  updateStatus('Scanning...', 'ok');

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs[0]?.url?.includes('mail.google.com')) {
      els.scanBtn.innerHTML = '🔍 Scan Current Email';
      els.scanBtn.disabled = false;
      updateStatus('Error: Open Gmail', 'offline');
      return;
    }

    chrome.tabs.sendMessage(tabs[0].id, { type: MSG.manualScan }, (resp) => {
      // Handle connection errors (e.g. content script outdated/not running)
      if (chrome.runtime.lastError) {
        console.warn('Connection error:', chrome.runtime.lastError.message);
        els.scanBtn.disabled = false;
        els.scanBtn.innerHTML = '🔍 Scan Current Email';
        updateStatus('Connection Failed', 'offline');
        els.hint.innerHTML = 'Please <b>refresh the Gmail tab</b> and try again.<br><span style="font-size:10px">(Extension was updated)</span>';
        els.hint.style.color = 'var(--danger)';
        return;
      }

      els.scanBtn.disabled = false;
      els.scanBtn.innerHTML = '🔍 Scan Current Email';

      if (resp && resp.success) {
        updateStatus('Scan Complete', 'ok');
        // Fetch from storage for full data
        setTimeout(() => {
          chrome.storage.local.get(['webshield_gmail_last_scan'], (r) => {
            if (r.webshield_gmail_last_scan) {
              renderResult(r.webshield_gmail_last_scan);
            }
          });
        }, 100);
      } else {
        updateStatus(resp?.error || 'Scan failed', 'offline');
        els.hint.textContent = resp?.error || 'Unable to scan this email';
      }
    });
  });
});

// Render scan results
function renderResult(data) {
  if (!data || !data.scanResult) return;

  els.resultArea.style.display = 'block';
  const res = data.scanResult;
  activeThreadId = data.emailId || activeThreadId;

  // Threat score and level
  const score = res.threat_score || 0;
  const level = (res.threat_level || 'unknown').toLowerCase();

  // Update threat badge
  els.threatBadge.textContent = level.toUpperCase();
  els.threatBadge.className = 'severity';
  if (level === 'safe' || score <= 33) {
    els.threatBadge.classList.add('safe');
  } else if (level === 'suspicious' || score <= 66) {
    els.threatBadge.classList.add('suspicious');
  } else {
    els.threatBadge.classList.add('dangerous');
  }

  // Score
  els.score.textContent = `Score: ${score}/100`;

  // Summary
  els.summary.textContent = res.summary || 'Analysis complete';

  // AI Explanation (optional)
  try {
    const ai = res.ai_explanation;
    const why = ai && typeof ai === 'object' ? (ai.why_marked || '') : '';
    const recos = ai && typeof ai === 'object' && Array.isArray(ai.recommendations)
      ? ai.recommendations.map(x => (x == null ? '' : String(x))).filter(Boolean)
      : [];

    if (els.aiContainer && els.aiWhy && els.aiRecos) {
      if (why) {
        els.aiContainer.style.display = 'block';
        els.aiWhy.textContent = why;
        els.aiRecos.innerHTML = recos.slice(0, 4).map(r => `<li>${r}</li>`).join('');
      } else {
        els.aiContainer.style.display = 'none';
        els.aiWhy.textContent = '';
        els.aiRecos.innerHTML = '';
      }
    }
  } catch (_) {
    if (els.aiContainer) els.aiContainer.style.display = 'none';
  }

  // Show offline badge if applicable
  if (els.offlineBadge) {
    els.offlineBadge.style.display = res.is_offline_analysis ? 'block' : 'none';
  }

  // Show threat reasons
  if (els.reasonsContainer && els.reasonsList && res.reasons && res.reasons.length > 0) {
    els.reasonsList.innerHTML = res.reasons.slice(0, 5).map(reason => {
      const isWarning = reason.startsWith('⚠️') || reason.includes('suspicious') || reason.includes('detected');
      const isPositive = reason.startsWith('✓') || reason.includes('safe') || reason.includes('passed');
      const className = isWarning ? 'warning' : (isPositive ? 'positive' : '');
      return `<li class="${className}">${reason}</li>`;
    }).join('');
    els.reasonsContainer.style.display = 'block';
  }

  // Stats
  const details = (res.details && typeof res.details === 'object') ? res.details : {};
  const senderRep = (details.sender_reputation && typeof details.sender_reputation === 'object') ? details.sender_reputation : {};
  const linkAnalysis = (details.link_analysis && typeof details.link_analysis === 'object') ? details.link_analysis : {};
  const contentAnalysis = (details.content_analysis && typeof details.content_analysis === 'object') ? details.content_analysis : {};

  const getLinksArray = () => {
    if (Array.isArray(linkAnalysis.links)) return linkAnalysis.links;
    if (Array.isArray(res.links)) return res.links;
    if (Array.isArray(res.link_details)) {
      return res.link_details
        .map(l => (typeof l === 'string' ? l : (l?.url || l?.href || null)))
        .filter(Boolean);
    }
    return [];
  };

  const computeUrlMismatches = () => {
    if (Number.isFinite(res.text_url_mismatches)) return res.text_url_mismatches;
    if (res.text_url_mismatches != null && !Number.isNaN(Number(res.text_url_mismatches))) {
      return Number(res.text_url_mismatches);
    }
    if (Array.isArray(res.link_details)) {
      return res.link_details.filter(l => l && typeof l === 'object' && !!l.textUrlMismatch).length;
    }
    const sl = Array.isArray(linkAnalysis.suspicious_links) ? linkAnalysis.suspicious_links : [];
    return sl.filter(l => l && typeof l === 'object' && !!l.textUrlMismatch).length;
  };

  const computeKeywordCount = () => {
    if (Number.isFinite(contentAnalysis.phishing_keywords_found)) return contentAnalysis.phishing_keywords_found;
    if (contentAnalysis.phishing_keywords_found != null && !Number.isNaN(Number(contentAnalysis.phishing_keywords_found))) {
      return Number(contentAnalysis.phishing_keywords_found);
    }
    const client = res.client_analysis;
    if (client && typeof client === 'object' && Array.isArray(client.clientFlags)) return client.clientFlags.length;
    return 0;
  };

  const linksArr = getLinksArray();
  const suspiciousLinksArr = Array.isArray(linkAnalysis.suspicious_links) ? linkAnalysis.suspicious_links : [];

  els.repScore.textContent = (senderRep.reputation_score ?? senderRep.score ?? '—');
  els.linkCount.textContent = (linkAnalysis.link_count ?? linksArr.length);

  // Details
  const isOffline = !!res.is_offline_analysis;
  if (senderRep.is_trusted_domain && !isOffline) {
    els.trusted.textContent = '✅ Verified';
  } else if (senderRep.is_trusted_domain && isOffline) {
    els.trusted.textContent = '➖ Trusted (offline)';
  } else {
    els.trusted.textContent = '❌ Not verified';
  }
  const ha = details.header_analysis || {};
  const spf = (ha.spf_status || 'unknown').toLowerCase();
  const dkim = (ha.dkim_status || 'unknown').toLowerCase();
  const dmarc = (ha.dmarc_status || 'unknown').toLowerCase();
  const gmailApiVerified = !!ha.gmail_api_verified;
  const anyFail = spf === 'fail' || dkim === 'fail' || dmarc === 'fail';
  const allUnknown = spf === 'unknown' && dkim === 'unknown' && dmarc === 'unknown';
  if (allUnknown) {
    const spfPosture = (ha.spf_posture || 'unknown').toLowerCase();
    const dkimPosture = (ha.dkim_posture || 'unknown').toLowerCase();
    const dmarcPosture = (ha.dmarc_posture || 'unknown').toLowerCase();
    const anyPostureKnown = spfPosture !== 'unknown' || dkimPosture !== 'unknown' || dmarcPosture !== 'unknown';


    if (anyPostureKnown) {
      const postureText = `DNS: SPF ${spfPosture}, DKIM ${dkimPosture}, DMARC ${dmarcPosture}`;
      els.auth.textContent = postureText;
    } else {
      els.auth.textContent = '❓ Unknown';
    }
  } else if (anyFail) {
    els.auth.textContent = gmailApiVerified ? '❌ Failed (Gmail API)' : '❌ Failed';
  } else if (ha.is_authenticated) {
    els.auth.textContent = gmailApiVerified ? '✅ Passed (Gmail API)' : '✅ Passed';
  } else {
    els.auth.textContent = gmailApiVerified ? '⚠️ Partial (Gmail API)' : '⚠️ Partial';
  }
  els.susLinks.textContent = suspiciousLinksArr.length;

  // Show URL mismatches if any
  const urlMismatches = computeUrlMismatches();
  if (els.urlMismatchRow && els.urlMismatches) {
    if (urlMismatches > 0) {
      els.urlMismatchRow.style.display = 'flex';
      els.urlMismatches.textContent = urlMismatches;
    } else {
      els.urlMismatchRow.style.display = 'none';
    }
  }

  // Show phishing keywords if detected
  const keywordsFound = computeKeywordCount();
  if (els.keywordsRow && els.phishingKeywords) {
    if (keywordsFound > 0) {
      els.keywordsRow.style.display = 'flex';
      els.phishingKeywords.textContent = keywordsFound;
      els.phishingKeywords.style.color = keywordsFound > 3 ? 'var(--danger)' : 'var(--warning)';
    } else {
      els.keywordsRow.style.display = 'none';
    }
  }

  // Update hint with context-aware message
  if (score <= 33) {
    els.hint.textContent = '✅ This email appears safe';
    els.hint.style.color = 'var(--success)';
  } else if (score <= 66) {
    els.hint.textContent = '⚠️ Be cautious with this email';
    els.hint.style.color = 'var(--warning)';
  } else {
    els.hint.textContent = '🚨 This email may be dangerous!';
    els.hint.style.color = 'var(--danger)';
  }
}

// Toggle extended tips
els.toggleTips?.addEventListener('click', () => {
  const isHidden = els.extendedTips.style.display === 'none';
  els.extendedTips.style.display = isHidden ? 'block' : 'none';
  els.toggleTips.textContent = isHidden ? 'Show Less' : 'Show More Tips';
});

// Report button - scroll to in-page report
els.reportBtn?.addEventListener('click', () => {
  const openReportForThread = (threadId) => {
    if (!threadId) return;
    const url = chrome.runtime.getURL(`report.html?id=${encodeURIComponent(threadId)}`);
    chrome.tabs.create({ url });
  };

  if (activeThreadId) {
    openReportForThread(activeThreadId);
    return;
  }

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs?.[0];
    const match = tab?.url?.match(/\/([A-Za-z0-9_-]+)$/);
    const threadId = (match && match[1].length > 5) ? match[1] : null;
    openReportForThread(threadId);
  });
});

// Quick action: Report Phishing
els.reportPhishing?.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
      chrome.tabs.sendMessage(tabs[0].id, {
        type: 'GMAIL_EXT_SAFETY_ACTION',
        action: 'report'
      }, (resp) => {
        if (resp?.success) {
          els.reportPhishing.textContent = '✓ Done';
          els.reportPhishing.disabled = true;
        }
      });
    }
  });
});

// Quick action: Mark Spam
els.markSpam?.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
      chrome.tabs.sendMessage(tabs[0].id, {
        type: 'GMAIL_EXT_SAFETY_ACTION',
        action: 'spam'
      }, (resp) => {
        if (resp?.success) {
          els.markSpam.textContent = '✓ Done';
          els.markSpam.disabled = true;
        }
      });
    }
  });
});

// Quick action: Show Details
els.showDetails?.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]?.id) {
      chrome.tabs.sendMessage(tabs[0].id, { type: 'GMAIL_EXT_SCROLL_TO_REPORT' });
    }
  });
});

// Settings button
els.settingsBtn?.addEventListener('click', () => {
  chrome.runtime.openOptionsPage?.() || chrome.tabs.create({ url: 'settings.html' });
});

// Start
init();

