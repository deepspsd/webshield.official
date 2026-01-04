// WebShield Gmail Settings - Enhanced Version
// Version 2.0.0

// Load settings
function loadSettings() {
    chrome.storage.sync.get({
        auto_scan: false,
        notifications: true,
        dark_mode: false,
        api_base_override: '',
        scan_timeout: 30
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

        // Apply dark mode
        if (settings.dark_mode) {
            document.body.classList.add('dark-mode');
        }
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

// Initialize
loadSettings();
