// WebShield Extension - Standardized Storage Utilities
// This file provides consistent scan ID storage across all extension components

/**
 * Store a scan result with standardized format
 * @param {string} scanId - The scan ID from the API
 * @param {string} url - The URL that was scanned
 * @param {string} type - Type of scan ('general', 'threat', 'ssl', 'manual')
 */
function storeScanResult(scanId, url, type = 'general') {
  if (!scanId || !url) {
    console.warn('WebShield: Cannot store scan result - missing scanId or url');
    return;
  }

  const timestamp = Date.now();
  const storageKey = `webshield_scan_${type}`;
  
  const scanData = {
    scanId: scanId,
    url: url,
    timestamp: timestamp,
    type: type,
    version: '1.0' // For future compatibility
  };
  
  chrome.storage.local.set({ [storageKey]: scanData }, () => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Failed to store scan result:', chrome.runtime.lastError);
    } else {
      console.log(`WebShield: Stored ${type} scan ID:`, scanId);
    }
  });
}

/**
 * Get the most recent scan result across all types
 * @param {function} callback - Callback function that receives the latest scan result
 */
function getLatestScanResult(callback) {
  chrome.storage.local.get(null, (allData) => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Failed to retrieve scan results:', chrome.runtime.lastError);
      callback(null);
      return;
    }

    const scanKeys = Object.keys(allData).filter(key => key.startsWith('webshield_scan_'));
    let latestScan = null;
    let latestTimestamp = 0;
    
    scanKeys.forEach(key => {
      const scanData = allData[key];
      if (scanData && scanData.timestamp && scanData.timestamp > latestTimestamp) {
        latestTimestamp = scanData.timestamp;
        latestScan = scanData;
      }
    });
    
    callback(latestScan);
  });
}

/**
 * Get scan result for a specific URL and type
 * @param {string} url - The URL to search for
 * @param {string} type - The scan type to search for (optional)
 * @param {function} callback - Callback function that receives the scan result
 */
function getScanResultByUrl(url, type, callback) {
  if (typeof type === 'function') {
    callback = type;
    type = null;
  }

  chrome.storage.local.get(null, (allData) => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Failed to retrieve scan results:', chrome.runtime.lastError);
      callback(null);
      return;
    }

    const scanKeys = Object.keys(allData).filter(key => {
      if (!key.startsWith('webshield_scan_')) return false;
      if (type && !key.endsWith(`_${type}`)) return false;
      return true;
    });

    let matchingScan = null;
    let latestTimestamp = 0;
    
    scanKeys.forEach(key => {
      const scanData = allData[key];
      if (scanData && scanData.url === url && scanData.timestamp > latestTimestamp) {
        latestTimestamp = scanData.timestamp;
        matchingScan = scanData;
      }
    });
    
    callback(matchingScan);
  });
}

/**
 * Clear expired scan results (older than specified time)
 * @param {number} maxAge - Maximum age in milliseconds (default: 1 hour)
 */
function clearExpiredScans(maxAge = 60 * 60 * 1000) {
  const cutoffTime = Date.now() - maxAge;
  
  chrome.storage.local.get(null, (allData) => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Failed to retrieve data for cleanup:', chrome.runtime.lastError);
      return;
    }

    const scanKeys = Object.keys(allData).filter(key => key.startsWith('webshield_scan_'));
    const expiredKeys = [];
    
    scanKeys.forEach(key => {
      const scanData = allData[key];
      if (scanData && scanData.timestamp && scanData.timestamp < cutoffTime) {
        expiredKeys.push(key);
      }
    });
    
    if (expiredKeys.length > 0) {
      chrome.storage.local.remove(expiredKeys, () => {
        if (chrome.runtime.lastError) {
          console.error('WebShield: Failed to clear expired scans:', chrome.runtime.lastError);
        } else {
          console.log('WebShield: Cleared expired scan data:', expiredKeys.length, 'items');
        }
      });
    }
  });
}

/**
 * Get all scan results with optional filtering
 * @param {object} options - Filter options {type, url, maxAge}
 * @param {function} callback - Callback function that receives array of scan results
 */
function getAllScanResults(options = {}, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  chrome.storage.local.get(null, (allData) => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Failed to retrieve scan results:', chrome.runtime.lastError);
      callback([]);
      return;
    }

    const scanKeys = Object.keys(allData).filter(key => key.startsWith('webshield_scan_'));
    const results = [];
    const cutoffTime = options.maxAge ? Date.now() - options.maxAge : 0;
    
    scanKeys.forEach(key => {
      const scanData = allData[key];
      if (!scanData || !scanData.timestamp) return;
      
      // Apply filters
      if (options.type && scanData.type !== options.type) return;
      if (options.url && scanData.url !== options.url) return;
      if (cutoffTime && scanData.timestamp < cutoffTime) return;
      
      results.push(scanData);
    });
    
    // Sort by timestamp (newest first)
    results.sort((a, b) => b.timestamp - a.timestamp);
    
    callback(results);
  });
}

/**
 * Clear all scan results
 * @param {function} callback - Optional callback function
 */
function clearAllScanResults(callback) {
  chrome.storage.local.get(null, (allData) => {
    if (chrome.runtime.lastError) {
      console.error('WebShield: Failed to retrieve data for clearing:', chrome.runtime.lastError);
      if (callback) callback(false);
      return;
    }

    const scanKeys = Object.keys(allData).filter(key => key.startsWith('webshield_scan_'));
    
    if (scanKeys.length === 0) {
      console.log('WebShield: No scan results to clear');
      if (callback) callback(true);
      return;
    }

    chrome.storage.local.remove(scanKeys, () => {
      if (chrome.runtime.lastError) {
        console.error('WebShield: Failed to clear scan results:', chrome.runtime.lastError);
        if (callback) callback(false);
      } else {
        console.log('WebShield: Cleared all scan results:', scanKeys.length, 'items');
        if (callback) callback(true);
      }
    });
  });
}

// Export functions for use in other files
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    storeScanResult,
    getLatestScanResult,
    getScanResultByUrl,
    clearExpiredScans,
    getAllScanResults,
    clearAllScanResults
  };
}
