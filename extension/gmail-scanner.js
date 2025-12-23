// WebShield Gmail Email Scanner
// Scans emails for phishing, malware, and suspicious content

console.log('🛡️ WebShield Gmail Scanner loaded');

// Configuration
const WEBSHIELD_CONFIG = {
    apiEndpoint: 'http://localhost:8000/api/email',
    scanDelay: 1500, // Wait 1.5s before auto-scanning
    
    // SCAN MODE: Choose one
    autoScan: false,  // ✅ RECOMMENDED: false = Show scan button (user control)
                      // ⚠️ true = Auto-scan every email (automatic, no button needed)
    
    showBadge: true,  // Show safety badge after scan
    useShadowDOM: true, // Use Shadow DOM for badge isolation (prevents Gmail CSS conflicts)
    useGmailAPI: false, // Enable Gmail API for accurate header analysis (requires OAuth setup)
    progressiveEnhancement: true, // Show fast DOM result first, then enhance with Gmail API
};

// State management
let currentEmailId = null;
let scanCache = new Map(); // Cache scan results
let isScanning = false;

// Get API base URL from storage
async function getAPIBaseURL() {
    try {
        const result = await chrome.storage.sync.get({ api_base_override: null });
        if (result && result.api_base_override) {
            return result.api_base_override.replace(/\/$/, '');
        }
    } catch (e) {
        console.error('Failed to get API base URL:', e);
    }
    return 'http://localhost:8000';
}

// Extract email metadata from Gmail DOM
function extractEmailMetadata() {
    console.log('🔍 DEBUG: Starting metadata extraction...');
    
    try {
        // Get sender email - try multiple selectors
        let senderEmail = null;
        let senderElement = document.querySelector('span.gD[email]');
        
        if (!senderElement) {
            // Fallback: try other common Gmail selectors
            senderElement = document.querySelector('span[email]');
        }
        if (!senderElement) {
            senderElement = document.querySelector('.gD[email]');
        }
        if (!senderElement) {
            // Try to find in email header area
            const headerArea = document.querySelector('.gs');
            if (headerArea) {
                senderElement = headerArea.querySelector('[email]');
            }
        }
        
        senderEmail = senderElement ? senderElement.getAttribute('email') : null;
        console.log('DEBUG: senderElement =', senderElement);
        console.log('DEBUG: senderEmail =', senderEmail);
        
        // Get sender name - try multiple selectors
        let senderName = null;
        let senderNameElement = document.querySelector('span.go');
        
        if (!senderNameElement) {
            senderNameElement = document.querySelector('.go');
        }
        if (!senderNameElement) {
            senderNameElement = document.querySelector('span[email] span');
        }
        if (!senderNameElement && senderElement) {
            // Try to get name from parent
            senderNameElement = senderElement.closest('.gD')?.querySelector('.go');
        }
        
        senderName = senderNameElement ? senderNameElement.textContent.trim() : null;
        console.log('DEBUG: senderNameElement =', senderNameElement);
        console.log('DEBUG: senderName =', senderName);
        
        // Get subject - try multiple selectors
        let subject = null;
        let subjectElement = document.querySelector('h2.hP');
        
        if (!subjectElement) {
            subjectElement = document.querySelector('.hP');
        }
        if (!subjectElement) {
            subjectElement = document.querySelector('h2[data-legacy-thread-id]');
        }
        if (!subjectElement) {
            // Try to find in header area
            const headerArea = document.querySelector('.ha');
            if (headerArea) {
                subjectElement = headerArea.querySelector('h2');
            }
        }
        
        subject = subjectElement ? subjectElement.textContent.trim() : null;
        console.log('DEBUG: subjectElement =', subjectElement);
        console.log('DEBUG: subject =', subject);
        
        // Extract all links from email body
        const emailBody = document.querySelector('div.a3s.aiL');
        console.log('DEBUG: emailBody =', emailBody);
        const links = [];
        if (emailBody) {
            const linkElements = emailBody.querySelectorAll('a[href]');
            console.log('DEBUG: linkElements =', linkElements);
            linkElements.forEach(link => {
                const href = link.getAttribute('href');
                if (href && href.startsWith('http')) {
                    links.push(href);
                }
            });
        }
        
        // Get email headers (simplified - Gmail doesn't expose all headers easily)
        const headers = {
            spf: 'unknown',
            dkim: 'unknown',
            dmarc: 'unknown'
        };
        
        // Check if email has "via" indicator (often means forwarded/suspicious)
        const viaElement = document.querySelector('span.gD[aria-label*="via"]');
        if (viaElement) {
            headers.via = viaElement.textContent;
        }
        
        // Get user's email (recipient)
        const userEmailElement = document.querySelector('div.gb_Ec');
        console.log('DEBUG: userEmailElement =', userEmailElement);
        const userEmail = userEmailElement ? userEmailElement.getAttribute('data-email') : null;
        console.log('DEBUG: userEmail =', userEmail);
        
        if (!senderEmail) {
            console.error('❌ Could not extract sender email');
            console.log('DEBUG: Available email elements:', document.querySelectorAll('[email]'));
            console.log('DEBUG: All span.gD elements:', document.querySelectorAll('span.gD'));
            return null;
        }
        
        return {
            sender_email: senderEmail,
            sender_name: senderName,
            subject: subject,
            links: links,
            attachment_hashes: [], // TODO: Implement attachment hash extraction
            headers: headers,
            user_email: userEmail
        };
        
    } catch (error) {
        console.error('Error extracting email metadata:', error);
        return null;
    }
}

// Generate unique email ID from current URL
function getCurrentEmailId() {
    // Gmail URL formats:
    // #inbox/FMfcgzQcqkwsPrVVCVkqlspkKvqVCLzq
    // #label/Important/FMfcgzQcqkwsPrVVCVkqlspkKvqVCLzq
    const hash = window.location.hash;
    const match = hash.match(/\/([A-Za-z0-9_-]+)$/);
    if (match && match[1].length > 10) {
        const id = match[1];
        // Throttle noisy logging to only when it changes
        if (window.__webshield_lastEmailId !== id) {
            console.log('Detected email ID:', id);
            window.__webshield_lastEmailId = id;
        }
        return id;
    }
    return null;
}

// Scan email metadata via backend API using background proxy (avoids CORS in Gmail)
async function scanEmailMetadata(metadata, timeout = 30000) {
    try {
        const response = await chrome.runtime.sendMessage({
            type: 'SCAN_EMAIL_METADATA',
            metadata,
            timeout
        });

        if (!response) {
            throw new Error('No response from background');
        }
        if (response.error) {
            throw new Error(response.error);
        }

        const result = response.data || response;
        console.log('📊 Scan result (background proxy):', result);
        return result;
    } catch (error) {
        console.error('❌ Failed to scan email via background proxy:', error);
        throw error; // Re-throw to be handled by caller
    }
}

// ===== GMAIL API INTEGRATION (Optional Enhanced Mode) =====

// Check if user has authorized Gmail API access
async function hasGmailAPIAccess() {
    try {
        const result = await chrome.storage.sync.get({ gmail_api_enabled: false });
        return result.gmail_api_enabled === true;
    } catch (e) {
        return false;
    }
}

// Request Gmail OAuth token
async function getGmailAuthToken() {
    return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ 
            action: 'GET_GMAIL_TOKEN' 
        }, (response) => {
            if (response && response.token) {
                resolve(response.token);
            } else {
                reject(new Error('Failed to get Gmail auth token'));
            }
        });
    });
}

// Fetch full email data from Gmail API
async function fetchEmailFromGmailAPI(messageId) {
    try {
        console.log('📨 Fetching email from Gmail API:', messageId);
        const token = await getGmailAuthToken();
        
        const response = await fetchWithTimeout(
            `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`,
            {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            },
            8000
        );
        
        if (!response.ok) {
            throw new Error(`Gmail API error: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('✅ Gmail API data received');
        return data;
        
    } catch (error) {
        console.error('❌ Failed to fetch from Gmail API:', error);
        return null;
    }
}

// Parse headers from Gmail API response
function parseGmailHeaders(gmailData) {
    if (!gmailData || !gmailData.payload || !gmailData.payload.headers) {
        return null;
    }
    
    const headers = gmailData.payload.headers;
    const getHeader = (name) => {
        const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
        return header ? header.value : null;
    };
    
    // Extract authentication results
    const authResults = getHeader('Authentication-Results') || '';
    const receivedSPF = getHeader('Received-SPF') || '';
    
    return {
        from: getHeader('From'),
        to: getHeader('To'),
        subject: getHeader('Subject'),
        date: getHeader('Date'),
        message_id: getHeader('Message-ID'),
        spf: parseAuthResult(receivedSPF, authResults, 'spf'),
        dkim: parseAuthResult('', authResults, 'dkim'),
        dmarc: parseAuthResult('', authResults, 'dmarc'),
        authentication_results: authResults,
        received_spf: receivedSPF,
    };
}

// Parse authentication results (SPF, DKIM, DMARC)
function parseAuthResult(receivedSPF, authResults, type) {
    const results = (receivedSPF + ' ' + authResults).toLowerCase();
    
    if (type === 'spf') {
        if (results.includes('spf=pass')) return 'pass';
        if (results.includes('spf=fail')) return 'fail';
        if (results.includes('spf=softfail')) return 'softfail';
        if (results.includes('spf=neutral')) return 'neutral';
    } else if (type === 'dkim') {
        if (results.includes('dkim=pass')) return 'pass';
        if (results.includes('dkim=fail')) return 'fail';
    } else if (type === 'dmarc') {
        if (results.includes('dmarc=pass')) return 'pass';
        if (results.includes('dmarc=fail')) return 'fail';
    }
    
    return 'unknown';
}

// Enhanced scan with Gmail API data
async function enhancedScanWithGmailAPI(domMetadata, gmailMessageId) {
    try {
        console.log('🔬 Running enhanced scan with Gmail API...');
        
        // Fetch full email from Gmail API
        const gmailData = await fetchEmailFromGmailAPI(gmailMessageId);
        if (!gmailData) {
            console.warn('⚠️ Could not fetch Gmail API data, falling back to DOM-only');
            return null;
        }
        
        // Parse headers
        const headers = parseGmailHeaders(gmailData);
        
        // Merge with DOM metadata
        const enhancedMetadata = {
            ...domMetadata,
            headers: headers,
            gmail_message_id: gmailMessageId,
            data_source: 'gmail_api'
        };
        
        console.log('✅ Enhanced metadata with Gmail API:', enhancedMetadata);
        
        // Send enhanced metadata to backend
        return await scanEmailMetadata(enhancedMetadata);
        
    } catch (error) {
        console.error('❌ Enhanced scan failed:', error);
        return null;
    }
}

// Create Shadow DOM host for badge (better isolation)
function createShadowHost() {
    let host = document.getElementById('webshield-shadow-host');
    if (!host) {
        host = document.createElement('div');
        host.id = 'webshield-shadow-host';
        host.style.cssText = 'position: fixed; top: 80px; right: 20px; z-index: 999999;';
        document.body.appendChild(host);
        
        // Attach shadow root
        if (!host.shadowRoot) {
            host.attachShadow({ mode: 'open' });
        }
    }
    return host;
}

// Create and inject comprehensive safety badge with full report
function createSafetyBadge(scanResult, useShadowDOM = true) {
    // Remove existing badge if any
    const existingBadge = document.querySelector('.webshield-email-badge');
    if (existingBadge) {
        existingBadge.remove();
    }
    
    // Remove existing shadow host badge
    const existingHost = document.getElementById('webshield-shadow-host');
    if (existingHost && existingHost.shadowRoot) {
        existingHost.shadowRoot.innerHTML = '';
    }
    
    // Create badge container
    const badge = document.createElement('div');
    badge.className = 'webshield-email-badge';
    badge.id = 'webshield-badge';
    badge.style.position = 'relative';
    
    // Determine badge style based on threat level
    let badgeClass = 'safe';
    let icon = '✅';
    let title = 'Email is Safe';
    
    if (scanResult.threat_level === 'dangerous') {
        badgeClass = 'dangerous';
        icon = '⛔';
        title = 'DANGEROUS EMAIL';
    } else if (scanResult.threat_level === 'suspicious') {
        badgeClass = 'suspicious';
        icon = '⚠️';
        title = 'SUSPICIOUS EMAIL';
    }
    
    badge.className += ` ${badgeClass}`;
    
    // Extract details
    const senderRep = scanResult.details.sender_reputation;
    const headerAnalysis = scanResult.details.header_analysis;
    const linkAnalysis = scanResult.details.link_analysis;
    
    // Build comprehensive badge HTML
    badge.innerHTML = `
        <button class="webshield-close-btn" id="webshield-close-badge-btn">×</button>
        
        <div class="webshield-badge-header">
            <span class="webshield-badge-icon">${icon}</span>
            <span class="webshield-badge-title">🛡️ ${title}</span>
            <span class="webshield-badge-score">Threat: ${scanResult.threat_score}/100</span>
        </div>
        
        <div class="webshield-badge-summary">
            <strong>📊 Scan Summary:</strong> ${scanResult.summary}
        </div>
        
        <!-- Statistics Grid -->
        <div class="webshield-stats-grid">
            <div class="webshield-stat-card reputation">
                <div class="webshield-stat-label">👤 Sender Reputation</div>
                <div class="webshield-stat-value">${senderRep.reputation_score}/100</div>
            </div>
            <div class="webshield-stat-card links">
                <div class="webshield-stat-label">🔗 Links Found</div>
                <div class="webshield-stat-value">${linkAnalysis.total_links}</div>
            </div>
            <div class="webshield-stat-card auth">
                <div class="webshield-stat-label">🔐 Authenticated</div>
                <div class="webshield-stat-value">${headerAnalysis.is_authenticated ? '✅' : '❌'}</div>
            </div>
            <div class="webshield-stat-card flags">
                <div class="webshield-stat-label">⚠️ Flags</div>
                <div class="webshield-stat-value">${senderRep.flags ? senderRep.flags.length : 0}</div>
            </div>
        </div>
        
        <!-- Detailed Report (Initially Hidden) -->
        <div class="webshield-badge-details" style="display: none;">
            
            <!-- Sender Reputation Section -->
            <div class="webshield-detail-section">
                <h4>👤 Sender Reputation Analysis</h4>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Reputation Score:</span>
                    <span class="webshield-detail-value">${senderRep.reputation_score}/100</span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Trusted Sender:</span>
                    <span class="webshield-detail-value">${senderRep.is_trusted ? '✅ Yes' : '❌ No'}</span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Domain:</span>
                    <span class="webshield-detail-value">${senderRep.domain}</span>
                </div>
                ${senderRep.flags && senderRep.flags.length > 0 ? `
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Security Flags:</span>
                    <span class="webshield-detail-value">${senderRep.flags.join(', ')}</span>
                </div>
                ` : ''}
            </div>
            
            <!-- Email Authentication Section -->
            <div class="webshield-detail-section">
                <h4>🔐 Email Authentication</h4>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">SPF Check:</span>
                    <span class="webshield-detail-value">
                        <span class="webshield-status-badge ${headerAnalysis.spf_status === 'pass' ? 'pass' : headerAnalysis.spf_status === 'fail' ? 'fail' : 'unknown'}">
                            ${headerAnalysis.spf_status}
                        </span>
                    </span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">DKIM Check:</span>
                    <span class="webshield-detail-value">
                        <span class="webshield-status-badge ${headerAnalysis.dkim_status === 'pass' ? 'pass' : headerAnalysis.dkim_status === 'fail' ? 'fail' : 'unknown'}">
                            ${headerAnalysis.dkim_status}
                        </span>
                    </span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">DMARC Status:</span>
                    <span class="webshield-detail-value">
                        <span class="webshield-status-badge ${headerAnalysis.dmarc_status === 'pass' ? 'pass' : headerAnalysis.dmarc_status === 'fail' ? 'fail' : 'unknown'}">
                            ${headerAnalysis.dmarc_status}
                        </span>
                    </span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Spoofing Detected:</span>
                    <span class="webshield-detail-value">${headerAnalysis.spoofing_detected ? '⚠️ Yes' : '✅ No'}</span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Authenticated:</span>
                    <span class="webshield-detail-value">${headerAnalysis.is_authenticated ? '✅ Yes' : '❌ No'}</span>
                </div>
            </div>
            
            <!-- Link Analysis Section -->
            <div class="webshield-detail-section">
                <h4>🔗 Link Analysis</h4>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Total Links:</span>
                    <span class="webshield-detail-value">${linkAnalysis.total_links}</span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Malicious Links:</span>
                    <span class="webshield-detail-value" style="color: ${linkAnalysis.malicious_count > 0 ? '#F44336' : '#4CAF50'};">
                        ${linkAnalysis.malicious_count}
                    </span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Suspicious Links:</span>
                    <span class="webshield-detail-value" style="color: ${linkAnalysis.suspicious_count > 0 ? '#FF9800' : '#4CAF50'};">
                        ${linkAnalysis.suspicious_count}
                    </span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Safe Links:</span>
                    <span class="webshield-detail-value" style="color: #4CAF50;">
                        ${linkAnalysis.safe_count}
                    </span>
                </div>
                
                ${linkAnalysis.links && linkAnalysis.links.length > 0 ? `
                <div style="margin-top: 10px;">
                    <strong>Links Found:</strong>
                    <div class="webshield-links-list">
                        ${linkAnalysis.links.map(link => `
                            <div class="webshield-link-item ${link.is_malicious ? 'malicious' : link.is_suspicious ? 'suspicious' : 'safe'}">
                                <span>${link.is_malicious ? '⛔' : link.is_suspicious ? '⚠️' : '✅'}</span>
                                <span style="flex: 1; word-break: break-all;">${link.url}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                ` : ''}
            </div>
            
            <!-- Scan Metadata -->
            <div class="webshield-detail-section">
                <h4>📝 Scan Information</h4>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Scan ID:</span>
                    <span class="webshield-detail-value" style="font-family: monospace; font-size: 11px;">${scanResult.scan_id}</span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Scanned At:</span>
                    <span class="webshield-detail-value">${new Date().toLocaleString()}</span>
                </div>
                <div class="webshield-detail-row">
                    <span class="webshield-detail-label">Scan Type:</span>
                    <span class="webshield-detail-value">Full Email Analysis</span>
                </div>
            </div>
            
            <!-- Recommendations -->
            ${scanResult.recommendations && scanResult.recommendations.length > 0 ? `
            <div class="webshield-recommendations">
                <h4>💡 Security Recommendations</h4>
                <ul>
                    ${scanResult.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            </div>
            ` : ''}
        </div>
        
        <button class="webshield-toggle-details">View Full Detailed Report ▼</button>
    `;
    
    // Add click handler for close button
    const closeBtn = badge.querySelector('#webshield-close-badge-btn');
    closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        console.log('🗑️ Closing badge...');
        
        // Remove shadow host if using Shadow DOM
        const shadowHost = document.getElementById('webshield-shadow-host');
        if (shadowHost) {
            shadowHost.remove();
        }
        
        // Also remove badge if in regular DOM
        badge.remove();
    });
    
    // Add click handler for details toggle
    const toggleBtn = badge.querySelector('.webshield-toggle-details');
    const detailsDiv = badge.querySelector('.webshield-badge-details');
    
    toggleBtn.addEventListener('click', () => {
        if (detailsDiv.style.display === 'none') {
            detailsDiv.style.display = 'block';
            toggleBtn.textContent = 'Hide Details ▲';
        } else {
            detailsDiv.style.display = 'none';
            toggleBtn.textContent = 'View Full Detailed Report ▼';
        }
    });
    
    // Inject badge into Gmail UI
    console.log('Attempting to inject badge...');
    
    if (useShadowDOM) {
        // Use Shadow DOM for better isolation
        console.log('✅ Using Shadow DOM for badge isolation');
        const host = createShadowHost();
        const shadowRoot = host.shadowRoot;
        
        // Inject CSS into shadow root
        const style = document.createElement('style');
        style.textContent = getBadgeStyles();
        shadowRoot.appendChild(style);
        
        // Append badge to shadow root
        shadowRoot.appendChild(badge);
        
        // Add click handler for close button in shadow DOM
        setTimeout(() => {
            const closeBtn = shadowRoot.querySelector('#webshield-close-badge-btn');
            if (closeBtn) {
                closeBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    console.log('🗑️ Closing badge from shadow DOM...');
                    host.remove();
                });
            }
        }, 100);
        
        console.log('✅ Badge injected into Shadow DOM');
    } else {
        // Try email header first (legacy mode)
        const emailHeader = document.querySelector('div.ha');
        if (emailHeader && emailHeader.parentElement) {
            console.log('✅ Injecting badge into email header');
            emailHeader.insertBefore(badge, emailHeader.firstChild);
        } else {
            // Floating badge fallback (more reliable)
            console.log('⚠️ Using floating badge (more reliable)');  
            badge.style.cssText += ' position: fixed; top: 80px; right: 20px; z-index: 999999; max-width: 450px; box-shadow: 0 4px 20px rgba(0,0,0,0.4);';
            document.body.appendChild(badge);
        }
        console.log('✅ Badge injected successfully');
    }
}

// Get badge CSS styles for Shadow DOM
function getBadgeStyles() {
    return `
        /* Import the external CSS or inline critical styles here */
        .webshield-email-badge {
            background: white;
            border-radius: 8px;
            padding: 16px;
            margin: 12px 0;
            border-left: 4px solid #4CAF50;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            max-width: 450px;
            max-height: 600px;
            overflow-y: auto;
            position: relative;
        }
        
        .webshield-email-badge.dangerous {
            border-left-color: #F44336;
            background: #FFEBEE;
        }
        
        .webshield-email-badge.suspicious {
            border-left-color: #FF9800;
            background: #FFF3E0;
        }
        
        .webshield-close-btn {
            position: absolute;
            top: 8px;
            right: 8px;
            background: none;
            border: none;
            font-size: 20px;
            cursor: pointer;
            color: #666;
            padding: 4px 8px;
            line-height: 1;
        }
        
        .webshield-close-btn:hover {
            color: #000;
        }
        
        .webshield-badge-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 12px;
        }
        
        .webshield-badge-icon {
            font-size: 24px;
        }
        
        .webshield-badge-title {
            font-weight: bold;
            font-size: 16px;
            flex: 1;
        }
        
        .webshield-badge-score {
            background: #E3F2FD;
            color: #1976D2;
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 13px;
        }
        
        .webshield-badge-summary {
            margin-bottom: 12px;
            color: #555;
        }
        
        .webshield-stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin: 16px 0;
        }
        
        .webshield-stat-card {
            background: #F5F5F5;
            padding: 12px;
            border-radius: 6px;
            text-align: center;
        }
        
        .webshield-stat-label {
            font-size: 12px;
            color: #666;
            margin-bottom: 4px;
        }
        
        .webshield-stat-value {
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }
        
        .webshield-badge-details {
            margin-top: 16px;
            border-top: 1px solid #E0E0E0;
            padding-top: 16px;
            max-height: 250px;
            overflow-y: auto;
            overflow-x: hidden;
        }
        
        .webshield-detail-section {
            margin-bottom: 16px;
        }
        
        .webshield-detail-section h4 {
            margin: 0 0 12px 0;
            font-size: 14px;
            color: #333;
        }
        
        .webshield-detail-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #F0F0F0;
        }
        
        .webshield-detail-label {
            font-weight: 500;
            color: #666;
        }
        
        .webshield-detail-value {
            color: #333;
        }
        
        .webshield-status-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .webshield-status-badge.pass {
            background: #C8E6C9;
            color: #2E7D32;
        }
        
        .webshield-status-badge.fail {
            background: #FFCDD2;
            color: #C62828;
        }
        
        .webshield-status-badge.unknown {
            background: #E0E0E0;
            color: #666;
        }
        
        .webshield-links-list {
            margin-top: 8px;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .webshield-link-item {
            display: flex;
            gap: 8px;
            padding: 6px;
            margin: 4px 0;
            border-radius: 4px;
            font-size: 12px;
        }
        
        .webshield-link-item.safe {
            background: #E8F5E9;
        }
        
        .webshield-link-item.suspicious {
            background: #FFF3E0;
        }
        
        .webshield-link-item.malicious {
            background: #FFEBEE;
        }
        
        .webshield-recommendations {
            background: #E3F2FD;
            padding: 12px;
            border-radius: 6px;
            margin-top: 12px;
        }
        
        .webshield-recommendations h4 {
            margin: 0 0 8px 0;
            font-size: 14px;
            color: #1565C0;
        }
        
        .webshield-recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        
        .webshield-recommendations li {
            margin: 4px 0;
            color: #424242;
        }
        
        .webshield-toggle-details {
            width: 100%;
            margin-top: 12px;
            padding: 10px;
            background: #2196F3;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 500;
        }
        
        .webshield-toggle-details:hover {
            background: #1976D2;
        }
    `;
}

// Fetch with timeout utility
async function fetchWithTimeout(url, options = {}, timeout = 10000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timeoutId);
        return res;
    } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            throw new Error('Request timed out (server may be busy)');
        }
        throw err;
    }
}

// Basic reachability check so we fail fast before long scans
async function ensureAPIReachable(apiBase) {
    try {
        // Use a short timeout so we don't block the main scan attempt
        const res = await fetchWithTimeout(apiBase, { method: 'GET' }, 4000);
        // Even a 404 means the host is reachable; only network errors/timeout should fail
        return res.ok || res.status >= 200;
    } catch (error) {
        console.error('❌ API reachability check failed:', error);
        throw new Error(`Backend not reachable at ${apiBase}. Start backend or update API URL in settings.`);
    }
}

// Update scan button state
function updateScanButtonState(scanning, text) {
    const btn = document.getElementById('webshield-scan-btn');
    if (!btn) return;
    btn.disabled = scanning;
    btn.innerHTML = text || (scanning ? '⏳ Scanning...' : '🛡️ Scan Email');
    // Also reflect state on title for accessibility
    btn.title = scanning ? 'Scanning in progress' : 'Scan this email with WebShield';
}

// Handle scan button click (called by event delegation)
let lastClickTime = 0;
async function handleScanClick() {
    // Debounce clicks
    const now = Date.now();
    if (now - lastClickTime < 1000) {
        console.debug('🛡️ WebShield: click debounced');
        return;
    }
    lastClickTime = now;
    
    console.log('🖱️ Scan button clicked via delegation!');
    
    updateScanButtonState(true);
    
    try {
        await scanCurrentEmail();
    } catch (error) {
        console.error('❌ Scan button error:', error);
        showErrorBadge(`Scan failed: ${error.message}`);
    } finally {
        updateScanButtonState(false);
    }
}

// Setup event delegation for scan button (survives DOM changes)
let eventDelegationAttached = false;
function setupEventDelegation() {
    if (eventDelegationAttached) {
        console.log('📌 Event delegation already attached');
        return;
    }
    
    console.log('📌 Setting up event delegation for scan button...');
    
    // Use event delegation on document to catch clicks even after DOM changes
    document.addEventListener('click', (e) => {
        let target = e.target;
        if (!target) return;
        
        // Check if clicked element is our scan button or inside it
        if (target.id === 'webshield-scan-btn' || (target.closest && target.closest('#webshield-scan-btn'))) {
            e.preventDefault();
            e.stopPropagation();
            handleScanClick();
        }
    }, true); // Use capture phase
    
    eventDelegationAttached = true;
    console.log('✅ Event delegation setup complete');
}

// Create manual scan button (stable ID, no inline listener)
function createScanButton() {
    // Check if button already exists
    if (document.getElementById('webshield-scan-btn')) {
        console.log('🔘 Scan button already exists');
        return;
    }
    
    console.log('🔘 Creating scan button...');
    
    const scanBtn = document.createElement('button');
    scanBtn.id = 'webshield-scan-btn';
    scanBtn.className = 'webshield-scan-button';
    scanBtn.type = 'button';
    scanBtn.innerHTML = '🛡️ Scan Email';
    scanBtn.title = 'Scan this email with WebShield';
    scanBtn.setAttribute('data-webshield', 'true');
    
    // NOTE: Click handler is handled by event delegation
    
    // Try multiple injection points for Gmail toolbar
    let injected = false;
    
    // Debug: Log all potential injection points
    console.log('🔍 DEBUG: Looking for injection points...');
    console.log('div.iH:', document.querySelector('div.iH'));
    console.log('div.ha:', document.querySelector('div.ha'));
    console.log('.aeF:', document.querySelector('.aeF'));
    console.log('.hP (subject):', document.querySelector('.hP'));
    
    // Try 1: PRIORITY - Right after subject line (most visible and clickable)
    const subjectArea = document.querySelector('.hP');
    if (subjectArea && subjectArea.parentElement && !injected) {
        console.log('✅ Injecting button after subject (.hP)');
        const btnContainer = document.createElement('div');
        btnContainer.style.cssText = 'margin: 8px 0; display: block !important; visibility: visible !important;';
        scanBtn.style.cssText = `
            display: inline-block !important;
            margin: 0 !important;
            padding: 8px 16px !important;
            background: #1a73e8 !important;
            color: white !important;
            border: none !important;
            border-radius: 4px !important;
            font-size: 14px !important;
            font-weight: 500 !important;
            cursor: pointer !important;
            transition: background 0.2s !important;
            pointer-events: auto !important;
            position: relative !important;
            z-index: 100 !important;
            visibility: visible !important;
            opacity: 1 !important;
        `;
        // Add hover effect
        scanBtn.onmouseenter = () => { scanBtn.style.background = '#1557b0 !important'; };
        scanBtn.onmouseleave = () => { scanBtn.style.background = '#1a73e8 !important'; };
        
        btnContainer.appendChild(scanBtn);
        subjectArea.parentElement.insertBefore(btnContainer, subjectArea.nextSibling);
        injected = true;
    }
    
    // Try 2: Email header area (sender info area)
    if (!injected) {
        const emailHeader = document.querySelector('div.ha');
        if (emailHeader) {
            console.log('✅ Injecting button into email header (div.ha)');
            const btnContainer = document.createElement('div');
            btnContainer.style.cssText = 'margin: 12px 0; display: block;';
            scanBtn.style.cssText = `
                display: inline-block;
                padding: 8px 16px;
                background: #1a73e8;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
                transition: background 0.2s;
                pointer-events: auto !important;
                z-index: 100;
            `;
            // Add hover effect
            scanBtn.onmouseenter = () => { scanBtn.style.background = '#1557b0'; };
            scanBtn.onmouseleave = () => { scanBtn.style.background = '#1a73e8'; };
            
            btnContainer.appendChild(scanBtn);
            emailHeader.insertBefore(btnContainer, emailHeader.firstChild);
            injected = true;
        }
    }
    
    // Try 3: Gmail action menu bar (newer Gmail - .aeF) with better styling
    if (!injected) {
        const actionMenu = document.querySelector('.aeF');
        if (actionMenu) {
            console.log('✅ Injecting button into action menu (.aeF)');
            scanBtn.style.cssText = `
                margin: 0 8px;
                pointer-events: auto !important;
                z-index: 1000;
                position: relative;
            `;
            actionMenu.appendChild(scanBtn);
            injected = true;
        }
    }
    
    // Try 5: Floating button as fallback (ALWAYS WORKS) - MORE PROMINENT
    if (!injected) {
        console.log('⚠️ Using floating button fallback');
        scanBtn.style.cssText = `
            position: fixed !important;
            top: 140px !important;
            right: 24px !important;
            z-index: 999999 !important;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
            color: white !important;
            border: none !important;
            padding: 12px 24px !important;
            border-radius: 8px !important;
            font-size: 15px !important;
            font-weight: 600 !important;
            cursor: pointer !important;
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4) !important;
            transition: all 0.3s ease !important;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
        `;
        
        // Add hover effect via JavaScript
        scanBtn.onmouseenter = () => {
            scanBtn.style.transform = 'translateY(-2px) !important';
            scanBtn.style.boxShadow = '0 8px 25px rgba(102, 126, 234, 0.5) !important';
        };
        scanBtn.onmouseleave = () => {
            scanBtn.style.transform = 'translateY(0) !important';
            scanBtn.style.boxShadow = '0 6px 20px rgba(102, 126, 234, 0.4) !important';
        };
        
        document.body.appendChild(scanBtn);
        injected = true;
    }
    
    console.log('✅ Scan button injected:', injected);
    return scanBtn;
}

// Main scan function
async function scanCurrentEmail() {
    if (isScanning) {
        console.warn('⚠️ Scan already in progress, skipping...');
        return;
    }
    
    isScanning = true;
    console.log('🔍 Starting email scan...');
    console.log('📍 Current URL:', window.location.href);
    console.log('📍 Email ID:', getCurrentEmailId());
    
    try {
        // Wait a bit for Gmail DOM to be ready
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        // Extract email metadata
        console.log('Calling extractEmailMetadata()...');
        const metadata = extractEmailMetadata();
        
        if (!metadata) {
            console.error('❌ Could not extract email metadata - email may not be fully loaded');
            console.error('🔍 DEBUG: Available DOM elements:');
            console.error('  - span.gD[email]:', document.querySelectorAll('span.gD[email]').length);
            console.error('  - span[email]:', document.querySelectorAll('span[email]').length);
            console.error('  - .ha:', document.querySelectorAll('.ha').length);
            console.error('  - .a3s.aiL:', document.querySelectorAll('.a3s.aiL').length);
            
            // Show error badge
            showErrorBadge('Could not extract email data. Email may not be fully loaded.');
            isScanning = false;
            return;
        }
        
        console.log('📧 Extracted metadata:', metadata);
        
        // Check cache first
        const emailId = getCurrentEmailId();
        if (emailId && scanCache.has(emailId)) {
            console.log('✅ Using cached scan result');
            const cachedResult = scanCache.get(emailId);
            createSafetyBadge(cachedResult);
            isScanning = false;
            return;
        }
        
        // Scan via API with timeout (FAST initial scan)
        console.log('📡 Calling API to scan email (DOM-based)...');
        // Increase timeout to 30s to give backend enough time for DNS/ML work on slow networks
        const scanResult = await scanEmailMetadata(metadata, 30000);
        
        if (!scanResult) {
            console.error('❌ API returned null/empty result');
            showErrorBadge('Failed to scan email. API may be offline. Check if backend server is running on http://localhost:8000');
            isScanning = false;
            return;
        }
        
        console.log('✅ Fast scan completed!');
        console.log('📊 Threat Level:', scanResult.threat_level);
        console.log('📊 Threat Score:', scanResult.threat_score);
        
        // Cache result
        if (emailId) {
            scanCache.set(emailId, scanResult);
            console.log('💾 Cached scan result for email:', emailId);
        }
        
        // Display badge with initial results
        createSafetyBadge(scanResult, WEBSHIELD_CONFIG.useShadowDOM);
        
        // Progressive Enhancement: Try Gmail API for accurate headers (if enabled)
        if (WEBSHIELD_CONFIG.useGmailAPI && WEBSHIELD_CONFIG.progressiveEnhancement) {
            console.log('🔬 Progressive enhancement: checking Gmail API access...');
            const hasAPIAccess = await hasGmailAPIAccess();
            
            if (hasAPIAccess && emailId) {
                // Show "Verifying..." indicator
                updateScanButtonState(true, '🔬 Verifying...');
                
                try {
                    const enhancedResult = await enhancedScanWithGmailAPI(metadata, emailId);
                    
                    if (enhancedResult) {
                        console.log('✅ Enhanced scan with Gmail API completed!');
                        console.log('📊 Enhanced Threat Level:', enhancedResult.threat_level);
                        
                        // Update cache with enhanced result
                        scanCache.set(emailId, enhancedResult);
                        
                        // Update badge with enhanced results
                        createSafetyBadge(enhancedResult, WEBSHIELD_CONFIG.useShadowDOM);
                        
                        // Show notification for dangerous emails
                        if (enhancedResult.threat_level === 'dangerous') {
                            console.log('⚠️ DANGEROUS EMAIL DETECTED (verified)!');
                            chrome.runtime.sendMessage({
                                type: 'DANGEROUS_EMAIL_DETECTED',
                                data: enhancedResult
                            });
                        }
                    } else {
                        console.log('ℹ️ Enhanced scan not available, using DOM-based result');
                    }
                } catch (error) {
                    console.warn('⚠️ Enhanced scan failed, using DOM-based result:', error);
                }
            } else {
                console.log('ℹ️ Gmail API not enabled, using DOM-based result');
            }
        }
        
        // Show notification for dangerous emails (initial result)
        if (scanResult.threat_level === 'dangerous') {
            console.log('⚠️ DANGEROUS EMAIL DETECTED! Sending notification...');
            chrome.runtime.sendMessage({
                type: 'DANGEROUS_EMAIL_DETECTED',
                data: scanResult
            });
        }
        
    } catch (error) {
        console.error('❌ Error scanning email:', error);
        console.error('Error stack:', error.stack);
        showErrorBadge(`Scan failed: ${error.message}`);
    } finally {
        console.log('✅ Resetting isScanning flag');
        isScanning = false;
    }
}

// Show error badge when scan fails
function showErrorBadge(message) {
    // Remove existing badges
    const existingBadge = document.querySelector('.webshield-email-badge');
    if (existingBadge) {
        existingBadge.remove();
    }
    
    // Remove shadow host if exists
    const existingShadowHost = document.getElementById('webshield-shadow-host');
    if (existingShadowHost) {
        existingShadowHost.remove();
    }
    
    const badge = document.createElement('div');
    badge.className = 'webshield-email-badge error-badge';
    badge.id = 'webshield-error-badge';
    badge.style.cssText = 'background: #ffebee; border-left: 4px solid #f44336; position: relative; padding: 16px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;';
    badge.innerHTML = `
        <button class="webshield-close-btn" id="webshield-error-close-btn" style="position: absolute; top: 8px; right: 8px; background: none; border: none; font-size: 20px; cursor: pointer; color: #666; padding: 4px 8px;">×</button>
        <div class="webshield-badge-header" style="display: flex; align-items: center; gap: 10px; margin-bottom: 12px;">
            <span class="webshield-badge-icon" style="font-size: 24px;">❌</span>
            <span class="webshield-badge-title" style="font-weight: bold; font-size: 16px;">Scan Failed</span>
        </div>
        <div class="webshield-badge-summary" style="margin-bottom: 12px; color: #555;">${message}</div>
        <div style="margin-top: 10px; font-size: 12px; color: #666; background: #fff3cd; padding: 12px; border-radius: 6px; border-left: 3px solid #ff9800;">
            <strong>⚠️ Troubleshooting:</strong><br><br>
            1. <strong>Check if backend server is running:</strong> <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">http://localhost:8000</code><br><br>
            2. <strong>Start backend:</strong> Run <code style="background: #f5f5f5; padding: 2px 6px; border-radius: 3px;">python start_server.py</code> in your backend folder<br><br>
            3. <strong>Verify server:</strong> Open <a href="http://localhost:8000" target="_blank" style="color: #2196F3;">http://localhost:8000</a> in new tab<br><br>
            4. <strong>Check console:</strong> Open browser console (F12) for detailed logs
        </div>
    `;
    
    // Add close button event listener
    setTimeout(() => {
        const closeBtn = badge.querySelector('#webshield-error-close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                console.log('🗑️ Closing error badge...');
                badge.remove();
            });
        }
    }, 100);
    
    // Inject as floating badge (more visible)
    badge.style.cssText += 'position: fixed; top: 80px; right: 20px; z-index: 999999; max-width: 450px; animation: slideIn 0.3s ease;';
    document.body.appendChild(badge);
    
    console.log('✅ Error badge displayed');
}

// Observe Gmail UI changes to detect email opens
let observationTimeout;
function observeGmailChanges() {
    let lastEmailId = null;
    
    const observer = new MutationObserver(() => {
        // Debounce observer callbacks
        if (observationTimeout) clearTimeout(observationTimeout);
        
        observationTimeout = setTimeout(() => {
            const emailId = getCurrentEmailId();
            
            // Check if email changed
            if (emailId && emailId !== lastEmailId) {
                lastEmailId = emailId;
                console.log('📬 New email opened:', emailId);
                
                // Add scan button
                createScanButton();
                
                // Auto-scan if enabled
                if (WEBSHIELD_CONFIG.autoScan) {
                    setTimeout(() => scanCurrentEmail(), WEBSHIELD_CONFIG.scanDelay);
                }
            }
            
            // Reinject button if Gmail's DOM changes removed it
            if (emailId && !document.getElementById('webshield-scan-btn')) {
                console.log('⚠️ Scan button missing, reinjecting...');
                createScanButton();
            }
        }, 250);
    });
    
    // Observe URL changes and DOM changes
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Also listen to URL changes
    let lastUrl = window.location.href;
    setInterval(() => {
        if (window.location.href !== lastUrl) {
            lastUrl = window.location.href;
            const emailId = getCurrentEmailId();
            if (emailId) {
                console.log('📬 Email changed via URL:', emailId);
                createScanButton();
                if (WEBSHIELD_CONFIG.autoScan) {
                    setTimeout(() => scanCurrentEmail(), WEBSHIELD_CONFIG.scanDelay);
                }
            }
        }
    }, 1000);
}

// Test badge injection (for debugging)
function testBadgeInjection() {
    console.log('🧪 Testing badge injection...');
    const test = document.createElement('div');
    test.id = 'webshield-test-badge';
    test.textContent = '✅ WebShield Test Badge - Injection works!';
    test.style.cssText = 'position:fixed;top:80px;right:20px;background:#4CAF50;color:white;padding:15px;z-index:999999;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,0.3);font-family:sans-serif;font-size:14px;max-width:300px;cursor:pointer;';
    test.onclick = () => test.remove();
    document.body.appendChild(test);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (test.parentElement) test.remove();
        console.log('🧪 Test badge removed');
    }, 5000);
}

// Initialize when Gmail is ready
function initGmailScanner() {
    console.log('🛡️ Initializing WebShield Gmail Scanner...');
    console.log('📍 Current URL:', window.location.href);
    console.log('📍 Hostname:', window.location.hostname);
    
    // Setup event delegation FIRST (before any buttons are created)
    setupEventDelegation();
    
    // Wait for Gmail to load
    const checkGmailReady = setInterval(() => {
        const gmailCanvas = document.querySelector('div[role="main"]');
        if (gmailCanvas) {
            clearInterval(checkGmailReady);
            console.log('✅ Gmail loaded, starting scanner');
            
            // Start observing
            observeGmailChanges();
            
            // Check if email is already open
            const emailId = getCurrentEmailId();
            if (emailId) {
                console.log('📧 Email already open, creating scan button...');
                setTimeout(() => {
                    createScanButton();
                    if (WEBSHIELD_CONFIG.autoScan) {
                        setTimeout(() => scanCurrentEmail(), WEBSHIELD_CONFIG.scanDelay);
                    }
                }, 1000);
            } else {
                console.log('📭 No email open yet, waiting for user to open one...');
            }
        }
    }, 500);
    
    // Timeout after 10 seconds
    setTimeout(() => {
        clearInterval(checkGmailReady);
        console.log('⏱️ Gmail ready check timeout');
    }, 10000);
}

// Listen for manual scan requests from popup
let manualScanInProgress = false;
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log('📨 Message received:', message);
    
    if (!message) {
        sendResponse({ success: false, error: 'Invalid message' });
        return true;
    }
    
    // Handle both 'type' and 'action' for compatibility
    const action = message.type || message.action;
    
    if (action === 'SCAN_EMAIL_MANUAL') {
        console.log('📧 Manual email scan requested from popup');
        
        // Guard against duplicate processing
        if (manualScanInProgress) {
            console.debug('⚠️ Manual scan already in progress');
            sendResponse({ success: false, error: 'Scan already in progress' });
            return true;
        }
        
        // Check if we're on Gmail
        if (window.location.hostname !== 'mail.google.com') {
            console.error('❌ Not on Gmail');
            sendResponse({ success: false, error: 'Not on Gmail' });
            return true;
        }
        
        // Check if an email is open
        const emailId = getCurrentEmailId();
        if (!emailId) {
            console.error('❌ No email is currently open');
            sendResponse({ success: false, error: 'No email is currently open' });
            return true;
        }
        
        console.log('✅ Starting manual scan for email:', emailId);
        manualScanInProgress = true;
        
        // Trigger scan
        handleScanClick().then(() => {
            console.log('✅ Manual scan completed successfully');
            sendResponse({ success: true, message: 'Email scan completed' });
        }).catch((error) => {
            console.error('❌ Manual scan error:', error);
            sendResponse({ success: false, error: 'Scan failed: ' + error.message });
        }).finally(() => {
            manualScanInProgress = false;
        });
        
        return true; // Keep message channel open for async response
    }
    
    // Test message handler
    if (action === 'TEST_BADGE') {
        testBadgeInjection();
        sendResponse({ success: true, message: 'Test badge injected' });
        return true;
    }
});

// Defensive wrapper to catch init errors
(() => {
    try {
        if (window.location.hostname === 'mail.google.com') {
            initGmailScanner();
        } else {
            console.log('🛡️ WebShield: Not on Gmail, scanner disabled');
        }
    } catch (err) {
        console.error('🛡️ WebShield: Uncaught error during scanner init', err);
        // Show debug banner
        try {
            const el = document.createElement('div');
            el.id = 'webshield-init-error';
            el.style.cssText = 'position:fixed;bottom:8px;right:8px;z-index:9999999;background:#fee;border:2px solid #f99;padding:8px 12px;font-size:12px;border-radius:4px;font-family:sans-serif;cursor:pointer;';
            el.textContent = '⚠️ WebShield init error — open console (F12)';
            el.onclick = () => el.remove();
            document.body.appendChild(el);
        } catch (ignored) {}
    }
})();