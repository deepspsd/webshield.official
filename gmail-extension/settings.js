// WebShield Gmail Settings - Enhanced Version
// Version 2.1.0

// Load settings
function loadSettings() {
    chrome.storage.sync.get({
        auto_scan: false,
        notifications: true,
        dark_mode: false,
        api_base_override: '',
        scan_timeout: 30,
        use_gmail_api: true,
        gmail_api_connected: false
    }, (settings) => {
        if (chrome.runtime.lastError) {
            console.error('Failed to load settings:', chrome.runtime.lastError);
            showStatus('Failed to load settings', true);
            return;
        }
        document.getElementById('auto-scan').checked = settings.auto_scan;
        document.getElementById('notifications').checked = settings.notifications;
        document.getElementById('dark-mode').checked = settings.dark_mode;
        document.getElementById('api-endpoint').value = settings.api_base_override || 'http://localhost:8000';
        document.getElementById('scan-timeout').value = settings.scan_timeout;
        document.getElementById('use-gmail-api').checked = settings.use_gmail_api;

        // Apply dark mode
        if (settings.dark_mode) {
            document.body.classList.add('dark-mode');
        }
        (async () => {
            try {
                if (globalThis.CryptoStorage && CryptoStorage.getEncrypted) {
                    const enc = await CryptoStorage.getEncrypted('gmail_api_token');
                    if (enc && enc.token && enc.expires_at && Date.now() < (enc.expires_at - 300000)) {
                        updateGmailApiUI(settings.use_gmail_api, true);
                        return;
                    }
                }
            } catch (_) {
                // ignore
            }
            chrome.storage.local.get(['gmail_api_token'], (result) => {
                if (chrome.runtime.lastError) return;
                const hasToken = !!result.gmail_api_token;
                updateGmailApiUI(settings.use_gmail_api, hasToken);
            });
        })();
    });
}

// Show status message
function showStatus(message, isError = false) {
    const statusEl = document.getElementById('status-message');
    statusEl.textContent = message;
    statusEl.className = 'status-message ' + (isError ? 'error' : 'success');
    statusEl.style.display = 'block';

    setTimeout(() => {
        statusEl.style.display = 'none';
    }, 3000);
}

// Save general settings
function saveGeneralSettings() {
    const autoScan = document.getElementById('auto-scan').checked;
    const notifications = document.getElementById('notifications').checked;
    const darkMode = document.getElementById('dark-mode').checked;

    chrome.storage.sync.set({
        auto_scan: autoScan,
        notifications: notifications,
        dark_mode: darkMode
    }, () => {
        if (chrome.runtime.lastError) {
            console.error('Failed to save settings:', chrome.runtime.lastError);
            showStatus('Failed to save settings', true);
            return;
        }
        showStatus('Settings saved successfully');
    });
}

// Event listeners for general settings
document.getElementById('auto-scan').addEventListener('change', saveGeneralSettings);
document.getElementById('notifications').addEventListener('change', saveGeneralSettings);
document.getElementById('dark-mode').addEventListener('change', (e) => {
    document.body.classList.toggle('dark-mode', e.target.checked);
    saveGeneralSettings();
});

// Save API settings
document.getElementById('save-api').addEventListener('click', () => {
    const apiEndpoint = document.getElementById('api-endpoint').value.trim();
    const scanTimeout = parseInt(document.getElementById('scan-timeout').value);

    // Local-only demo mode: only allow localhost endpoints
    let parsed;
    try {
        parsed = new URL(apiEndpoint);
    } catch (_) {
        showStatus('Please enter a valid URL (example: http://localhost:8000)', true);
        return;
    }
    const isLocalHost = (parsed.protocol === 'http:' && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'));
    if (!isLocalHost) {
        showStatus('Local demo mode: only http://localhost or http://127.0.0.1 endpoints are allowed', true);
        return;
    }

    if (!apiEndpoint) {
        showStatus('Please enter a valid API endpoint', true);
        return;
    }

    if (scanTimeout < 10 || scanTimeout > 120) {
        showStatus('Scan timeout must be between 10 and 120 seconds', true);
        return;
    }

    chrome.storage.sync.set({
        api_base_override: apiEndpoint,
        scan_timeout: scanTimeout
    }, () => {
        if (chrome.runtime.lastError) {
            console.error('Failed to save API settings:', chrome.runtime.lastError);
            showStatus('Failed to save API settings', true);
            return;
        }
        showStatus('API settings saved successfully');
    });
});

// Clear history
document.getElementById('clear-history').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all scan history?')) {
        chrome.storage.local.get(null, (items) => {
            const scanKeys = Object.keys(items).filter(key =>
                key.startsWith('webshield_') || key.startsWith('gmail_report_')
            );

            if (scanKeys.length > 0) {
                chrome.storage.local.remove(scanKeys, () => {
                    showStatus(`Cleared ${scanKeys.length} scan records`);
                });
            } else {
                showStatus('No scan history to clear');
            }
        });
    }
});

// Clear cache
document.getElementById('clear-cache').addEventListener('click', () => {
    if (confirm('Are you sure you want to clear the cache?')) {
        chrome.storage.local.clear(() => {
            showStatus('Cache cleared successfully');
        });
    }
});

// Gmail API UI update function (global so loadSettings can use it)
let updateGmailApiUI = () => { }; // placeholder

// Gmail API Settings - Wrap in DOMContentLoaded to ensure elements exist
document.addEventListener('DOMContentLoaded', () => {
    const useGmailApiCheckbox = document.getElementById('use-gmail-api');
    const gmailApiStatus = document.getElementById('gmail-api-status');
    const gmailApiConnect = document.getElementById('gmail-api-connect');
    const gmailApiDisconnect = document.getElementById('gmail-api-disconnect');
    const gmailApiIcon = document.getElementById('gmail-api-icon');
    const gmailApiText = document.getElementById('gmail-api-text');
    const gmailApiDetails = document.getElementById('gmail-api-details');

    if (!useGmailApiCheckbox || !gmailApiConnect) {
        console.error('Gmail API UI elements not found');
        return;
    }

    // Define the real update function
    updateGmailApiUI = function (enabled, connected) {
        if (!gmailApiStatus) return;
        if (enabled) {
            gmailApiStatus.style.display = 'block';
            if (connected) {
                if (gmailApiIcon) gmailApiIcon.textContent = '✅';
                if (gmailApiText) gmailApiText.textContent = 'Connected to Gmail API';
                if (gmailApiDetails) gmailApiDetails.textContent = 'Real SPF/DKIM/DMARC verification enabled';
                gmailApiConnect.style.display = 'none';
                if (gmailApiDisconnect) gmailApiDisconnect.style.display = 'inline-block';
            } else {
                if (gmailApiIcon) gmailApiIcon.textContent = '❌';
                if (gmailApiText) gmailApiText.textContent = 'Not connected';
                if (gmailApiDetails) gmailApiDetails.textContent = 'Connect to enable real email authentication verification';
                gmailApiConnect.style.display = 'inline-block';
                if (gmailApiDisconnect) gmailApiDisconnect.style.display = 'none';
            }
        } else {
            gmailApiStatus.style.display = 'none';
        }
    };

    // Initialize settings after DOM is ready
    loadSettings();

    useGmailApiCheckbox.addEventListener('change', () => {
        const enabled = useGmailApiCheckbox.checked;
        chrome.storage.sync.set({ use_gmail_api: enabled }, () => {
            if (enabled) {
                showStatus('Gmail API enabled. Please connect your account.');
                (async () => {
                    try {
                        if (globalThis.CryptoStorage && CryptoStorage.getEncrypted) {
                            const enc = await CryptoStorage.getEncrypted('gmail_api_token');
                            if (enc && enc.token && enc.expires_at && Date.now() < (enc.expires_at - 300000)) {
                                updateGmailApiUI(true, true);
                                return;
                            }
                        }
                    } catch (_) {
                        // ignore
                    }
                    chrome.storage.local.get(['gmail_api_token'], (result) => {
                        updateGmailApiUI(true, !!result.gmail_api_token);
                    });
                })();
            } else {
                showStatus('Gmail API disabled');
                updateGmailApiUI(false, false);
            }
        });
    });

    gmailApiConnect.addEventListener('click', async () => {
        try {
            gmailApiConnect.disabled = true;
            gmailApiConnect.textContent = 'Connecting...';

            chrome.runtime.sendMessage({ type: 'GMAIL_API_AUTH' }, (response) => {
                gmailApiConnect.disabled = false;
                gmailApiConnect.textContent = 'Connect Gmail';

                if (chrome.runtime.lastError) {
                    showStatus('Connection failed: ' + chrome.runtime.lastError.message, true);
                    return;
                }

                if (response && response.success) {
                    showStatus('Successfully connected to Gmail API!');
                    updateGmailApiUI(true, true);
                } else {
                    showStatus(response?.error || 'Connection failed', true);
                }
            });
        } catch (err) {
            gmailApiConnect.disabled = false;
            gmailApiConnect.textContent = 'Connect Gmail';
            showStatus('Connection error: ' + err.message, true);
        }
    });

    if (gmailApiDisconnect) {
        gmailApiDisconnect.addEventListener('click', () => {
            if (confirm('Disconnect from Gmail API?')) {
                chrome.runtime.sendMessage({ type: 'GMAIL_API_DISCONNECT' }, (response) => {
                    // Check for runtime error first
                    if (chrome.runtime.lastError) {
                        const errorMsg = chrome.runtime.lastError.message || 'Unknown error';
                        console.error('Gmail API disconnect failed:', errorMsg);
                        showStatus('Failed to disconnect from Gmail API: ' + errorMsg, true);
                        return;
                    }
                    
                    // Check if response indicates failure
                    if (!response || !response.success) {
                        const errorMsg = (response && response.error) ? response.error : 'Unknown error';
                        console.error('Gmail API disconnect failed:', errorMsg);
                        showStatus('Failed to disconnect from Gmail API: ' + errorMsg, true);
                        return;
                    }
                    
                    // Success case
                    showStatus('Disconnected from Gmail API');
                    updateGmailApiUI(true, false);
                });
            }
        });
    }
});
