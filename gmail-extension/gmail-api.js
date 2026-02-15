/**
 * WebShield Gmail API Integration Module
 * Handles OAuth authentication with Google and fetches real email headers
 * for SPF/DKIM/DMARC verification via Gmail API
 * Version 2.1.0
 */

(function () {
  'use strict';

  const GMAIL_API_BASE = 'https://www.googleapis.com/gmail/v1';
  const DEBUG_MODE = true; // TEMPORARILY enabled for OAuth debugging

  const log = {
    info: (...args) => DEBUG_MODE && console.log('[GmailAPI]', ...args),
    warn: (...args) => console.warn('[GmailAPI]', ...args),
    error: (...args) => console.error('[GmailAPI]', ...args)
  };

  // OAuth configuration - populated from manifest
  let oauthConfig = {
    clientId: null,
    scopes: [
      'https://www.googleapis.com/auth/gmail.metadata',
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/userinfo.email'
    ]
  };

  // Token cache
  let cachedToken = null;
  let tokenExpiry = null;

  async function loadTokenFromStorage() {
    try {
      if (globalThis.CryptoStorage && CryptoStorage.getEncrypted) {
        const enc = await CryptoStorage.getEncrypted('gmail_api_token');
        if (enc && enc.token && enc.expires_at) {
          cachedToken = enc.token;
          tokenExpiry = enc.expires_at;
          if (Date.now() < tokenExpiry - 300000) {
            return true;
          }

          cachedToken = null;
          tokenExpiry = null;
          return false;
        }
      }

      const stored = await chrome.storage.local.get(['gmail_api_token', 'gmail_api_token_expiry']);
      if (stored.gmail_api_token && stored.gmail_api_token_expiry) {
        const expiry = stored.gmail_api_token_expiry;
        if (Date.now() < expiry - 300000) {
          cachedToken = stored.gmail_api_token;
          tokenExpiry = expiry;
          if (globalThis.CryptoStorage && CryptoStorage.setEncrypted) {
            try {
              await CryptoStorage.setEncrypted('gmail_api_token', {
                token: stored.gmail_api_token,
                stored_at: Date.now(),
                expires_at: expiry,
                verified: true,
                email: null
              });
              try {
                await chrome.storage.local.remove(['gmail_api_token', 'gmail_api_token_expiry']);
              } catch (_) { /* ignore */ }
            } catch (_) {
              // ignore
            }
          }
          return true;
        }
      }
    } catch (_) {
      // ignore
    }
    cachedToken = null;
    tokenExpiry = null;
    return false;
  }

  async function fetchMessageFull(messageId, _retryCount = 0, { threadIdFallback = null } = {}) {
    const MAX_RETRIES = 1;
    try {
      if (!isAuthenticated()) {
        const auth = await authenticate();
        if (!auth.success) {
          throw new Error('Authentication required');
        }
      }

      const response = await fetch(
        `${GMAIL_API_BASE}/users/me/messages/${encodeURIComponent(messageId)}?format=full`,
        {
          headers: {
            'Authorization': `Bearer ${cachedToken}`,
            'Accept': 'application/json'
          }
        }
      );

      if (!response.ok) {
        if (response.status === 404 && threadIdFallback && _retryCount < MAX_RETRIES) {
          const resolved = await fetchThreadFirstMessageId(threadIdFallback);
          if (resolved && resolved !== messageId) {
            return fetchMessageFull(resolved, _retryCount + 1, { threadIdFallback: null });
          }
        }

        if ((response.status === 401 || response.status === 403) && _retryCount < MAX_RETRIES) {
          cachedToken = null;
          tokenExpiry = null;
          try { await chrome.storage.local.remove(['gmail_api_token', 'gmail_api_token_expiry']); } catch (_) { /* ignore */ }
          try {
            if (globalThis.CryptoStorage && CryptoStorage.removeEncrypted) {
              await CryptoStorage.removeEncrypted('gmail_api_token');
            }
          } catch (_) { /* ignore */ }

          const auth = await authenticate();
          if (auth.success) {
            return fetchMessageFull(messageId, _retryCount + 1, { threadIdFallback });
          }
        }

        let errorBody = '';
        try { errorBody = await response.text(); } catch (_) { /* ignore */ }
        throw new Error(`Gmail API error: ${response.status} ${response.statusText} - ${errorBody}`);
      }

      const data = await response.json();
      return { success: true, data };
    } catch (err) {
      return { success: false, error: err.message, data: null };
    }
  }

  function _collectAttachmentsFromPayload(payload, out) {
    if (!payload || typeof payload !== 'object') return;
    const parts = Array.isArray(payload.parts) ? payload.parts : [];
    for (const part of parts) {
      if (!part || typeof part !== 'object') continue;
      const filename = part.filename || '';
      const body = part.body || {};
      const attachmentId = body.attachmentId || null;
      const size = body.size || 0;
      const mimeType = part.mimeType || '';

      if (filename && attachmentId) {
        out.push({ filename, attachmentId, size, mimeType });
      }
      if (part.parts) {
        _collectAttachmentsFromPayload(part, out);
      }
    }
  }

  async function listMessageAttachments(messageId, { threadIdFallback = null } = {}) {
    const full = await fetchMessageFull(messageId, 0, { threadIdFallback });
    if (!full.success) {
      return { success: false, error: full.error, attachments: [] };
    }
    const payload = full.data?.payload || null;
    const out = [];
    _collectAttachmentsFromPayload(payload, out);
    return { success: true, attachments: out, messageId: full.data?.id || messageId };
  }

  function _base64UrlToBytes(b64url) {
    if (!b64url || typeof b64url !== 'string') return new Uint8Array();
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
    const raw = atob(b64 + pad);
    const arr = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
    return arr;
  }

  async function fetchAttachmentBytes(messageId, attachmentId) {
    if (!messageId || !attachmentId) {
      return { success: false, error: 'Missing messageId or attachmentId', bytes: null };
    }
    try {
      if (!isAuthenticated()) {
        const auth = await authenticate();
        if (!auth.success) throw new Error('Authentication required');
      }

      const response = await fetch(
        `${GMAIL_API_BASE}/users/me/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}`,
        {
          headers: {
            'Authorization': `Bearer ${cachedToken}`,
            'Accept': 'application/json'
          }
        }
      );

      if (!response.ok) {
        let body = '';
        try { body = await response.text(); } catch (_) { /* ignore */ }
        throw new Error(`Gmail API attachment error: ${response.status} ${response.statusText} - ${body}`);
      }

      const data = await response.json().catch(() => null);
      const bytes = _base64UrlToBytes(data?.data || '');
      return { success: true, bytes, size: data?.size || bytes.length };
    } catch (e) {
      return { success: false, error: e?.message || 'Attachment fetch failed', bytes: null };
    }
  }

  /**
   * Initialize Gmail API module
   */
  async function init() {
    try {
      // Try to load OAuth config from chrome.identity
      const manifest = chrome.runtime.getManifest();
      if (manifest.oauth2) {
        oauthConfig.clientId = manifest.oauth2.client_id;
        if (manifest.oauth2.scopes) {
          oauthConfig.scopes = manifest.oauth2.scopes;
        }
      }

      await loadTokenFromStorage();

      log.info('Gmail API module initialized');
    } catch (err) {
      log.error('Failed to initialize Gmail API module:', err);
    }
  }

  /**
   * Check if user is authenticated with Gmail API
   */
  function isAuthenticated() {
    return cachedToken !== null && Date.now() < tokenExpiry - 300000;
  }

  /**
   * Authenticate with Google OAuth via Chrome Identity API
   * Uses background script for OAuth flow since chrome.identity isn't available in content scripts
   */
  async function authenticate() {
    try {
      log.info('Starting OAuth authentication via background script...');

      // Send message to background script to handle OAuth
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'GMAIL_API_AUTH' }, (result) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(result);
          }
        });
      });

      if (!response || !response.success) {
        throw new Error(response?.error || 'Authentication failed');
      }

      const ok = await loadTokenFromStorage();
      if (ok && cachedToken) {
        log.info('OAuth authentication successful, token cached');
        return { success: true, token: cachedToken };
      }
      throw new Error('No token received from background script');

    } catch (err) {
      log.error('OAuth authentication failed:', err);
      return { success: false, error: err.message };
    }
  }

  /**
   * Disconnect from Gmail API
   * Uses background script to handle disconnect since chrome.identity isn't available in content scripts
   */
  async function disconnect() {
    try {
      // Send message to background script to handle disconnect
      const response = await new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'GMAIL_API_DISCONNECT' }, (result) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(result);
          }
        });
      });

      cachedToken = null;
      tokenExpiry = null;

      if (response && response.success) {
        log.info('Gmail API disconnected');
        return { success: true };
      } else {
        throw new Error(response?.error || 'Disconnect failed');
      }
    } catch (err) {
      log.error('Disconnect failed:', err);
      // Still clear local cache even if server disconnect failed
      cachedToken = null;
      tokenExpiry = null;
      return { success: false, error: err.message };
    }
  }

  /**
   * Fetch message metadata from Gmail API
   * Uses gmail.metadata scope - gets headers but not full body
   * @param {string} messageId - The Gmail message ID
   * @param {number} _retryCount - Internal retry counter to prevent infinite loops
   */
  async function fetchMessageMetadata(messageId, _retryCount = 0, { threadIdFallback = null } = {}) {
    const MAX_RETRIES = 1;
    try {
      if (!isAuthenticated()) {
        const auth = await authenticate();
        if (!auth.success) {
          throw new Error('Authentication required');
        }
      }

      log.info('Fetching message metadata for:', messageId, 'threadIdFallback:', threadIdFallback);

      const response = await fetch(
        `${GMAIL_API_BASE}/users/me/messages/${encodeURIComponent(messageId)}?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Subject&metadataHeaders=Authentication-Results&metadataHeaders=Received-SPF&metadataHeaders=DKIM-Signature&metadataHeaders=DMARC-Filter&metadataHeaders=Reply-To&metadataHeaders=Return-Path&metadataHeaders=Received`,
        {
          headers: {
            'Authorization': `Bearer ${cachedToken}`,
            'Accept': 'application/json'
          }
        }
      );

      if (!response.ok) {
        // 404 Not Found: messageId might be a web-only ID. Try thread fallback if available.
        if (response.status === 404 && threadIdFallback && _retryCount < MAX_RETRIES) {
          log.warn(`Message ${messageId} not found (404); trying threadId ${threadIdFallback}`);
          const resolved = await fetchThreadFirstMessageId(threadIdFallback);
          if (resolved && resolved !== messageId) {
            return fetchMessageMetadata(resolved, _retryCount + 1, { threadIdFallback: null });
          }
        }

        // 400 Invalid id value: most commonly we passed a THREAD id from the Gmail URL.
        if (response.status === 400 && _retryCount < MAX_RETRIES) {
          let errorBody = '';
          try { errorBody = await response.text(); } catch (_) { /* ignore */ }
          const lower = String(errorBody || '').toLowerCase();
          const looksLikeInvalidId = lower.includes('invalid id value') || lower.includes('invalidargument');
          if (looksLikeInvalidId) {
            log.warn('Gmail API returned 400 invalid id; attempting threadId -> messageId resolution. Body:', errorBody);
            const resolved = await fetchThreadFirstMessageId(messageId);
            if (resolved) {
              return fetchMessageMetadata(resolved, _retryCount + 1, { threadIdFallback: null });
            }
          }
        }

        // 401 = token expired, 403 = insufficient scope / stale token
        // Both need re-authentication with correct scopes
        if ((response.status === 401 || response.status === 403) && _retryCount < MAX_RETRIES) {
          let errorBody = '';
          try { errorBody = await response.text(); } catch (_) { /* ignore */ }
          log.warn(`Gmail API returned ${response.status}, forcing re-auth (attempt ${_retryCount + 1}). Body:`, errorBody);

          // Clear stale token so authenticate() fetches a fresh one
          cachedToken = null;
          tokenExpiry = null;
          // Also clear stored token to force a fresh OAuth consent
          try {
            await chrome.storage.local.remove(['gmail_api_token', 'gmail_api_token_expiry']);
          } catch (_) { /* ignore */ }

          try {
            if (globalThis.CryptoStorage && CryptoStorage.removeEncrypted) {
              await CryptoStorage.removeEncrypted('gmail_api_token');
            }
          } catch (_) { /* ignore */ }

          const auth = await authenticate();
          if (auth.success) {
            return fetchMessageMetadata(messageId, _retryCount + 1);
          }
          throw new Error(`Gmail API re-auth failed after ${response.status}`);
        }

        let errorBody = '';
        try { errorBody = await response.text(); } catch (_) { /* ignore */ }
        throw new Error(`Gmail API error: ${response.status} ${response.statusText} - ${errorBody}`);
      }

      const data = await response.json();
      log.info('Message metadata fetched successfully');

      return {
        success: true,
        data: parseMessageHeaders(data)
      };

    } catch (err) {
      log.error('Failed to fetch message metadata:', err);
      return {
        success: false,
        error: err.message,
        data: null
      };
    }
  }

  /**
   * Given a Gmail threadId, fetch the first message id.
   * Gmail UI URLs typically contain thread ids, not message ids.
   */
  async function fetchThreadFirstMessageId(threadId) {
    try {
      if (!threadId) return null;
      if (!isAuthenticated()) {
        const auth = await authenticate();
        if (!auth.success) return null;
      }

      const resp = await fetch(
        `${GMAIL_API_BASE}/users/me/threads/${threadId}?format=metadata`,
        {
          headers: {
            'Authorization': `Bearer ${cachedToken}`,
            'Accept': 'application/json'
          }
        }
      );

      if (!resp.ok) {
        let body = '';
        try { body = await resp.text(); } catch (_) { /* ignore */ }
        log.warn(`Failed to resolve threadId to messageId: ${resp.status} ${resp.statusText}`, body);
        return null;
      }

      const data = await resp.json().catch(() => null);
      const firstMsgId = data?.messages?.[0]?.id || null;
      return firstMsgId;
    } catch (e) {
      log.warn('ThreadId resolution failed:', e?.message);
      return null;
    }
  }

  /**
   * Parse Gmail API message response and extract auth headers
   */
  function parseMessageHeaders(messageData) {
    const headers = {};
    const payload = messageData.payload || {};
    const headerList = payload.headers || [];

    // Extract all headers by name
    for (const header of headerList) {
      const k = String(header.name || '').toLowerCase();
      if (!k) continue;
      if (headers[k] === undefined) {
        headers[k] = header.value;
      } else if (Array.isArray(headers[k])) {
        headers[k].push(header.value);
      } else {
        headers[k] = [headers[k], header.value];
      }
    }

    // Parse Authentication-Results header for SPF/DKIM/DMARC
    const authResults = headers['authentication-results'] || '';
    const parsedAuth = parseAuthenticationResults(authResults);

    // Parse Received-SPF if present
    const receivedSpf = headers['received-spf'] || '';

    return {
      messageId: messageData.id,
      threadId: messageData.threadId,
      snippet: messageData.snippet,
      headers: {
        from: headers.from,
        to: headers.to,
        subject: headers.subject,
        replyTo: headers['reply-to'],
        returnPath: headers['return-path'],
        received: headers['received']
      },
      authentication: {
        spf: parsedAuth.spf || parseReceivedSPF(receivedSpf),
        dkim: parsedAuth.dkim,
        dmarc: parsedAuth.dmarc,
        rawResults: authResults
      }
    };
  }

  /**
   * Parse Authentication-Results header
   * Format: "domain; mechanism1=value; mechanism2=value; ..."
   */
  function parseAuthenticationResults(headerValue) {
    const result = {
      spf: null,
      dkim: null,
      dmarc: null
    };

    if (!headerValue) return result;

    try {
      // Look for SPF result
      const spfMatch = headerValue.match(/spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i);
      if (spfMatch) {
        result.spf = spfMatch[1].toLowerCase();
      }

      // Look for DKIM result
      const dkimMatch = headerValue.match(/dkim=(pass|fail|neutral|none|temperror|permerror)/i);
      if (dkimMatch) {
        result.dkim = dkimMatch[1].toLowerCase();
      }

      // Look for DMARC result
      const dmarcMatch = headerValue.match(/dmarc=(pass|fail|none|temperror|permerror)/i);
      if (dmarcMatch) {
        result.dmarc = dmarcMatch[1].toLowerCase();
      }

      log.info('Parsed auth results:', result);
    } catch (err) {
      log.error('Failed to parse Authentication-Results:', err);
    }

    return result;
  }

  /**
   * Parse Received-SPF header as fallback
   */
  function parseReceivedSPF(headerValue) {
    if (!headerValue) return null;

    const match = headerValue.match(/(pass|fail|softfail|neutral|none)/i);
    return match ? match[1].toLowerCase() : null;
  }

  /**
   * Extract Gmail message ID from URL or DOM
   */
  function looksLikeGmailApiId(id) {
    if (!id || typeof id !== 'string') return false;
    const s = id.trim();
    if (s.length < 10) return false;

    // Reject pure numeric strings of 19+ digits (likely web UI legacy IDs)
    if (/^\d{19,}$/.test(s)) return false;

    // Gmail API message/thread ids are typically hex-ish strings with mixed chars
    // Accept alphanumeric with dashes/underscores, but not pure numeric
    return /^[a-zA-Z0-9_-]+$/.test(s) && s.length >= 16 && /[a-zA-Z]/.test(s);
  }

  function looksLikeGmailWebId(id) {
    if (!id || typeof id !== 'string') return false;
    const trimmed = id.trim();

    // Gmail web UI uses 16-char hex IDs like "19c56c6e375bc45b"
    if (/^[a-f0-9]{16}$/i.test(trimmed)) return true;

    // Some Gmail web UI IDs are long numeric strings (19+ digits) that fail API validation
    // API IDs are typically mixed alphanumeric, not pure numeric
    if (/^\d{19,}$/.test(trimmed)) return true;

    return false;
  }

  // Try to find real Gmail API ID from Gmail's exposed global objects
  function findIdInGmailGlobals() {
    try {
      // Gmail exposes various global objects with message data
      // GM_SPT is one common object that contains thread/message info
      if (typeof window.GM_SPT !== 'undefined' && window.GM_SPT) {
        const data = window.GM_SPT;
        // Look for threadId or messageId in various properties
        const threadId = data.t || data.threadId || data.thread_id || null;
        const messageId = data.m || data.messageId || data.message_id || data.msgId || null;
        if (messageId || threadId) {
          log.info('Found ID in GM_SPT:', { messageId, threadId });
          return { messageId, threadId };
        }
      }

      // Try gmail's main app globals
      if (window.GMAIL_GLOBALS) {
        const g = window.GMAIL_GLOBALS;
        if (g.threadId || g.messageId) {
          return {
            messageId: g.messageId || null,
            threadId: g.threadId || null
          };
        }
      }

      // Look for any global with 'thread' in the name that has an ID
      for (const key in window) {
        if (key.toLowerCase().includes('thread') || key.toLowerCase().includes('message')) {
          const val = window[key];
          if (val && typeof val === 'object') {
            const id = val.id || val.threadId || val.messageId || val.t || val.m;
            if (id && typeof id === 'string' && id.length > 10) {
              log.info(`Found potential ID in window.${key}:`, id);
            }
          }
        }
      }
    } catch (e) {
      // Ignore - globals access can fail
    }
    return null;
  }

  // Try to find ID from the email view's URL parameters or inline data
  function findIdFromGmailView() {
    // Gmail sometimes stores IDs in specific view elements
    const viewContainers = [
      '[data-view-id]',
      '[role="main"]',
      '.aAU', // Gmail main container
      '.adn', // Email view container
      '.h7',  // Another email container
      '.ii.gt', // Message body container
    ];

    for (const selector of viewContainers) {
      const el = document.querySelector(selector);
      if (el) {
        // Check data attributes
        const attrs = ['data-thread-id', 'data-message-id', 'data-item-id', 'data-id', 'data-legacy-id', 'id'];
        for (const attr of attrs) {
          const val = el.getAttribute(attr);
          if (val && val.length > 10) {
            const normalized = normalizeCandidateId(val);
            log.info(`Checking ${selector}[${attr}]:`, val, 'normalized:', normalized, 'isWebId:', looksLikeGmailWebId(normalized), 'isApiId:', looksLikeGmailApiId(normalized));
            if (looksLikeGmailApiId(normalized) && !looksLikeGmailWebId(normalized)) {
              log.info(`Found API ID in ${selector}[${attr}]:`, normalized);
              return { messageId: normalized, threadId: null };
            }
          }
        }
      }
    }

    // Try to find in iframe (email content)
    const iframes = document.querySelectorAll('iframe');
    for (const iframe of iframes) {
      try {
        const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
        if (iframeDoc) {
          const body = iframeDoc.querySelector('body');
          if (body) {
            // Check for message ID in the email body comments or data attributes
            const html = iframeDoc.documentElement.innerHTML;
            const msgIdMatch = html.match(/Message-ID:\s*<([^>]+)>/i);
            if (msgIdMatch) {
              log.info('Found Message-ID in email body:', msgIdMatch[1]);
            }
          }
        }
      } catch (e) {
        // Cross-origin iframe, can't access
      }
    }

    return null;
  }

  /**
   * Search for a message using sender and subject via Gmail API
   * This is more reliable than extracting IDs from DOM
   */
  async function searchMessageByContent(senderEmail, subject, maxResults = 5) {
    try {
      if (!isAuthenticated()) {
        const auth = await authenticate();
        if (!auth.success) return null;
      }

      // Build search query
      let query = '';
      if (senderEmail) {
        query += `from:${senderEmail} `;
      }
      if (subject) {
        // Escape special characters in subject
        const escapedSubject = subject.replace(/"/g, '\\"').substring(0, 100);
        query += `subject:"${escapedSubject}" `;
      }
      query += 'in:inbox newer_than:1d'; // Recent emails only

      log.info('Searching Gmail with query:', query);

      const searchUrl = `${GMAIL_API_BASE}/users/me/messages?q=${encodeURIComponent(query)}&maxResults=${maxResults}`;
      const response = await fetch(searchUrl, {
        headers: {
          'Authorization': `Bearer ${cachedToken}`,
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        // Handle 403 - insufficient scope (need to re-auth with more scopes)
        if (response.status === 403) {
          const bodyText = await response.text().catch(() => "");
          if (bodyText.toLowerCase().includes("insufficient permission") ||
            bodyText.toLowerCase().includes("scope")) {
            log.warn('Gmail search failed due to insufficient scope (gmail.readonly required). Clearing token and re-authenticating...');
            // Clear token to force re-auth with correct scopes
            cachedToken = null;
            tokenExpiry = null;
            try {
              await chrome.storage.local.remove(['gmail_api_token', 'gmail_api_token_expiry']);
            } catch (_) { /* ignore */ }
            try {
              if (globalThis.CryptoStorage && CryptoStorage.removeEncrypted) {
                await CryptoStorage.removeEncrypted('gmail_api_token');
              }
            } catch (_) { /* ignore */ }

            // Re-authenticate with updated scopes and retry once
            const reauth = await authenticate();
            if (reauth.success && cachedToken) {
              log.info('Re-authenticated with updated scopes, retrying search...');
              const retryResponse = await fetch(searchUrl, {
                headers: {
                  'Authorization': `Bearer ${cachedToken}`,
                  'Accept': 'application/json'
                }
              });
              if (retryResponse.ok) {
                const retryData = await retryResponse.json();
                const retryMessages = retryData?.messages || [];
                if (retryMessages.length > 0) {
                  log.info('Found message via search (after re-auth):', retryMessages[0].id);
                  return retryMessages[0].id;
                }
              }
            }
            return null;
          }
        }
        log.warn('Gmail search failed:', response.status, response.statusText);
        return null;
      }

      const data = await response.json();
      const messages = data?.messages || [];

      if (messages.length === 0) {
        log.info('No messages found matching query');
        return null;
      }

      // Return the first (most recent) message ID
      log.info('Found message via search:', messages[0].id);
      return messages[0].id;

    } catch (err) {
      log.error('Search failed:', err);
      return null;
    }
  }
  function debugGmailIds() {
    const debug = {
      globals: findIdInGmailGlobals(),
      dom: {},
      url: window.location.hash,
      timestamp: Date.now()
    };

    // Use TreeWalker for efficient element traversal
    const treeWalker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_ELEMENT,
      null,
      false
    );

    let el;
    while ((el = treeWalker.nextNode()) !== null) {
      const attrs = el.getAttributeNames();
      for (const attr of attrs) {
        if (attr.startsWith('data-') && (attr.includes('id') || attr.includes('message') || attr.includes('thread'))) {
          const val = el.getAttribute(attr);
          if (val && val.length > 8) {
            if (!debug.dom[attr]) debug.dom[attr] = [];
            if (debug.dom[attr].length < 3) {
              // Safe class extraction: handle SVGAnimatedString and other non-string className
              const cls = typeof el.className === 'string' ? el.className : (el.getAttribute('class') || '');
              debug.dom[attr].push({
                value: val,
                normalized: normalizeCandidateId(val),
                isWebId: looksLikeGmailWebId(normalizeCandidateId(val)),
                isApiId: looksLikeGmailApiId(normalizeCandidateId(val)),
                tag: el.tagName,
                class: cls.substring(0, 50)
              });
            }
          }
        }
      }
    }

    log.info('Gmail ID Debug Info:', debug);
    return debug;
  }

  function normalizeCandidateId(raw) {
    if (!raw || typeof raw !== 'string') return null;
    let s = raw.trim();
    if (!s) return null;
    // Remove common prefixes
    s = s.replace(/^#/, '');
    // Gmail sometimes includes wrappers like "msg-f:" etc.
    s = s.replace(/^msg-f:/i, '');
    s = s.replace(/^thread-f:/i, '');
    // Keep only alnum characters if it contains separators
    if (/[^A-Za-z0-9]/.test(s)) {
      s = (s.match(/[A-Za-z0-9]+/g) || []).join('');
    }
    return s || null;
  }

  function extractGmailIds() {
    // First try to find IDs from Gmail's global objects
    const globalsId = findIdInGmailGlobals();
    if (globalsId) {
      return globalsId;
    }

    // Try view-based extraction
    const viewId = findIdFromGmailView();
    if (viewId) {
      return viewId;
    }

    // Prefer DOM-derived IDs (more likely to be Gmail API-compatible)
    const legacyMsgEl = document.querySelector('[data-legacy-message-id]');
    const legacyThreadEl = document.querySelector('[data-legacy-thread-id]');
    const msgEl = document.querySelector('[data-message-id]');

    const legacyMsgIdRaw = legacyMsgEl?.getAttribute('data-legacy-message-id');
    const legacyThreadIdRaw = legacyThreadEl?.getAttribute('data-legacy-thread-id');
    const dataMsgIdRaw = msgEl?.getAttribute('data-message-id');

    log.info('Raw DOM IDs:', { legacyMsgIdRaw, legacyThreadIdRaw, dataMsgIdRaw });

    // Check for API-compatible IDs first
    let messageId = null;
    let threadId = null;
    let hasWebOnlyId = false;

    // Check data-message-id (most likely to be API-compatible)
    if (dataMsgIdRaw) {
      const normalized = normalizeCandidateId(dataMsgIdRaw);
      if (looksLikeGmailApiId(normalized) && !looksLikeGmailWebId(normalized)) {
        messageId = normalized;
      }
    }

    // Check legacy message ID
    if (!messageId && legacyMsgIdRaw) {
      if (looksLikeGmailWebId(legacyMsgIdRaw)) {
        hasWebOnlyId = true;
        log.info('Legacy message ID is web UI format only:', legacyMsgIdRaw);
      } else {
        const normalized = normalizeCandidateId(legacyMsgIdRaw);
        if (looksLikeGmailApiId(normalized) && !looksLikeGmailWebId(normalized)) {
          messageId = normalized;
        }
      }
    }

    // Check thread ID - ONLY use if it's API-compatible (not web UI ID)
    if (legacyThreadIdRaw) {
      if (looksLikeGmailWebId(legacyThreadIdRaw)) {
        hasWebOnlyId = true;
        log.info('Legacy thread ID is web UI format only:', legacyThreadIdRaw);
        // DO NOT use web UI thread IDs - they cause 400 errors from Gmail API
        threadId = null;
      } else {
        const normalized = normalizeCandidateId(legacyThreadIdRaw);
        if (looksLikeGmailApiId(normalized) && !looksLikeGmailWebId(normalized)) {
          threadId = normalized;
        }
      }
    }

    log.info('Extracted IDs:', { messageId, threadId, hasWebOnlyId });

    // If we have valid API IDs, return them
    if (messageId || threadId) {
      return { messageId, threadId, hasWebOnlyId };
    }

    // If we only have web IDs, we can't use Gmail API - return early
    if (hasWebOnlyId) {
      log.info('Web UI IDs detected — will use search fallback to resolve API ID');
      return { messageId: null, threadId: null, hasWebOnlyId: true };
    }

    // Fallback: try URL hash if no DOM IDs found
    const hash = window.location.hash;
    const match = hash.match(/\/([A-Za-z0-9_-]+)$/);
    const urlIdRaw = match?.[1] || null;

    if (urlIdRaw) {
      // Check if URL ID is web-only format
      if (looksLikeGmailWebId(urlIdRaw)) {
        log.warn('URL contains web UI ID only:', urlIdRaw);
        return { messageId: null, threadId: null, hasWebOnlyId: true };
      }

      const urlId = normalizeCandidateId(urlIdRaw);
      if (looksLikeGmailApiId(urlId) && !looksLikeGmailWebId(urlId)) {
        log.info('Using API ID from URL:', urlId);
        return { messageId: urlId, threadId: null, hasWebOnlyId: false };
      }
    }

    return { messageId: null, threadId: null, hasWebOnlyId: false };
  }

  // Backward compatible helper (previously exported)
  function extractGmailMessageId() {
    const ids = extractGmailIds();
    return ids.messageId || null;
  }

  /**
   * Get authentication status for current email
   * This is the main function called by the scanner
   * @param {Object} metadata - Optional metadata with sender_email and subject for search fallback
   */
  async function getCurrentEmailAuth(metadata = null) {
    try {
      const ids = extractGmailIds();
      let messageId = ids.messageId;
      let threadId = ids.threadId;

      // Only try thread resolution if we have an API-compatible threadId
      if (!messageId && threadId) {
        messageId = await fetchThreadFirstMessageId(threadId);
      }

      // Check if user has enabled Gmail API
      const settings = await chrome.storage.sync.get({
        use_gmail_api: true,
        gmail_api_connected: false
      });

      if (!settings.use_gmail_api) {
        return {
          success: false,
          error: 'Gmail API not enabled in settings',
          auth: null,
          disabled: true
        };
      }

      // If no valid IDs found and metadata provided, try searching by sender and subject
      // This is the fallback when we only have web UI IDs or no IDs at all
      // Search fallback disabled per user request
      if (!messageId && metadata && metadata.sender_email) {
        console.log('[GmailAPI] Search fallback skipped (user disabled)');
      } else if (!messageId) {
        console.warn('[GmailAPI] ❌ Cannot use search fallback: no metadata.sender_email provided');
      }

      // If still no messageId after all attempts, report failure
      if (!messageId) {
        if (ids.hasWebOnlyId) {
          return {
            success: false,
            error: 'Unable to locate email via Gmail API. Web UI IDs cannot be used directly, and search by sender/subject did not match. The email may be too old.',
            auth: null,
            webOnlyId: true
          };
        }
        return {
          success: false,
          error: 'No email message ID found',
          auth: null
        };
      }

      log.info('Final IDs for API call:', { messageId, threadId, hasWebOnlyId: ids.hasWebOnlyId });

      const result = await fetchMessageMetadata(messageId, 0, { threadIdFallback: threadId });

      if (!result.success && result.error && result.error.includes('404')) {
        // If we have threadId but messageId failed, try thread directly
        if (threadId) {
          log.info('Message 404, trying thread resolution');
          const resolved = await fetchThreadFirstMessageId(threadId);
          if (resolved) {
            const retryResult = await fetchMessageMetadata(resolved, 0, { threadIdFallback: null });
            if (retryResult.success) {
              return {
                success: true,
                auth: retryResult.data.authentication,
                messageId: retryResult.data.messageId,
                headers: retryResult.data.headers
              };
            }
          }
        }
      }

      if (!result.success) {
        return {
          success: false,
          error: result.error,
          auth: null
        };
      }

      return {
        success: true,
        auth: result.data.authentication,
        messageId: result.data.messageId,
        headers: result.data.headers
      };

    } catch (err) {
      log.error('Failed to get email auth:', err);
      return {
        success: false,
        error: err.message,
        auth: null
      };
    }
  }

  /**
   * Check connection status and prompt for auth if needed
   */
  async function ensureAuthenticated() {
    if (isAuthenticated()) {
      return { success: true };
    }

    return await authenticate();
  }

  async function generateEmailExplanation(scanData) {
    try {
      // Get API base from settings or fallback
      const apiBase = await (async () => {
        try {
          const settings = await chrome.storage.sync.get({ api_base_override: null });
          if (settings.api_base_override && settings.api_base_override.startsWith('http')) {
            return settings.api_base_override.replace(/\/$/, '');
          }
        } catch (_) { }
        return 'http://localhost:8000';
      })();

      const response = await fetch(`${apiBase}/api/email/explain-threat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          threat_score: scanData.threat_score || 0,
          threat_level: scanData.threat_level || 'unknown',
          summary: scanData.summary || '',
          reasons: scanData.reasons || [],
          sender_email: scanData.sender_email || '',
          details: {
            sender_reputation: scanData.details?.sender_reputation || {},
            header_analysis: scanData.details?.header_analysis || {},
            link_analysis: scanData.details?.link_analysis || {},
            content_analysis: scanData.details?.content_analysis || {},
            attachments: scanData.details?.attachments || [],
            has_dangerous_attachments: scanData.details?.has_dangerous_attachments || false
          }
        })
      });

      if (!response.ok) {
        return { success: false, error: `HTTP ${response.status}` };
      }

      const data = await response.json();
      return {
        success: true,
        explanation: data.explanation || null
      };
    } catch (err) {
      log.error('Failed to generate AI explanation:', err);
      return { success: false, error: err?.message || 'Request failed' };
    }
  }

  // Initialize on load
  init();

  // Expose public API
  window.WebShieldGmailAPI = {
    isAuthenticated,
    authenticate,
    disconnect,
    fetchMessageMetadata,
    fetchMessageFull,
    getCurrentEmailAuth,
    ensureAuthenticated,
    listMessageAttachments,
    fetchAttachmentBytes,
    extractGmailMessageId,
    extractGmailIds,
    debugGmailIds,
    searchMessageByContent,
    generateEmailExplanation
  };

  log.info('Gmail API module loaded');
})();
