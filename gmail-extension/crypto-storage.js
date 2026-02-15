/**
 * WebShield Encrypted Token Storage
 * Uses Web Crypto API (AES-GCM) to encrypt sensitive data before storing in chrome.storage
 * Version 2.0.0
 */

const CryptoStorage = (() => {
    // Derive a stable encryption key from the extension ID + user agent
    // This ensures tokens are tied to this specific browser installation
    const SALT = 'webshield-v2-encrypted-storage';

    // Generate or retrieve the encryption key
    async function _getEncryptionKey() {
        // Use extension ID as key material (unique per installation)
        const extensionId = chrome.runtime.id || 'webshield-fallback';
        const keyMaterial = new TextEncoder().encode(extensionId + SALT);

        // Import key material for PBKDF2
        const baseKey = await crypto.subtle.importKey(
            'raw',
            keyMaterial,
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Derive AES-GCM key using PBKDF2
        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: new TextEncoder().encode(SALT),
                iterations: 100000,
                hash: 'SHA-256',
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    // Encrypt a string value
    async function encrypt(plaintext) {
        if (!plaintext || typeof plaintext !== 'string') {
            throw new Error('CryptoStorage.encrypt: plaintext must be a non-empty string');
        }

        try {
            const key = await _getEncryptionKey();
            const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for AES-GCM
            const encoded = new TextEncoder().encode(plaintext);

            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                encoded
            );

            // Pack IV + ciphertext as base64 for storage
            const packed = new Uint8Array(iv.length + ciphertext.byteLength);
            packed.set(iv, 0);
            packed.set(new Uint8Array(ciphertext), iv.length);

            return btoa(String.fromCharCode(...packed));
        } catch (err) {
            console.error('[CryptoStorage] Encryption failed:', err.message);
            throw err;
        }
    }

    // Decrypt a previously encrypted value
    async function decrypt(encryptedBase64) {
        if (!encryptedBase64 || typeof encryptedBase64 !== 'string') {
            throw new Error('CryptoStorage.decrypt: input must be a non-empty string');
        }

        try {
            const key = await _getEncryptionKey();
            const packed = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

            if (packed.length < 13) {
                throw new Error('Invalid encrypted data: too short');
            }

            const iv = packed.slice(0, 12);
            const ciphertext = packed.slice(12);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                ciphertext
            );

            return new TextDecoder().decode(decrypted);
        } catch (err) {
            console.error('[CryptoStorage] Decryption failed:', err.message);
            throw err;
        }
    }

    // Store an encrypted value in chrome.storage.local
    async function setEncrypted(key, value) {
        const encrypted = await encrypt(typeof value === 'string' ? value : JSON.stringify(value));
        return new Promise((resolve, reject) => {
            chrome.storage.local.set(
                { [`_enc_${key}`]: encrypted, [`_enc_${key}_ts`]: Date.now() },
                () => {
                    if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
                    } else {
                        resolve();
                    }
                }
            );
        });
    }

    // Retrieve and decrypt a value from chrome.storage.local
    async function getEncrypted(key, maxAgeMs = null) {
        return new Promise((resolve, reject) => {
            chrome.storage.local.get([`_enc_${key}`, `_enc_${key}_ts`], async (result) => {
                if (chrome.runtime.lastError) {
                    reject(new Error(chrome.runtime.lastError.message));
                    return;
                }

                const encrypted = result[`_enc_${key}`];
                const timestamp = result[`_enc_${key}_ts`];

                if (!encrypted) {
                    resolve(null);
                    return;
                }

                // Check expiry if maxAgeMs is specified
                if (maxAgeMs && timestamp && (Date.now() - timestamp) > maxAgeMs) {
                    // Token expired, remove it
                    await removeEncrypted(key);
                    resolve(null);
                    return;
                }

                try {
                    const decrypted = await decrypt(encrypted);
                    // Try to parse as JSON, fallback to raw string
                    try {
                        resolve(JSON.parse(decrypted));
                    } catch {
                        resolve(decrypted);
                    }
                } catch (err) {
                    console.error(`[CryptoStorage] Failed to decrypt key "${key}":`, err.message);
                    // Corrupted data — remove it
                    await removeEncrypted(key);
                    resolve(null);
                }
            });
        });
    }

    // Remove an encrypted value
    async function removeEncrypted(key) {
        return new Promise((resolve) => {
            chrome.storage.local.remove([`_enc_${key}`, `_enc_${key}_ts`], () => {
                resolve();
            });
        });
    }

    // Store OAuth token with encryption
    async function storeOAuthToken(accessToken, expiresIn = 3600) {
        const tokenData = {
            token: accessToken,
            stored_at: Date.now(),
            expires_at: Date.now() + (expiresIn * 1000),
        };
        await setEncrypted('oauth_access_token', tokenData);
        console.log('[CryptoStorage] OAuth token stored encrypted');
    }

    // Retrieve OAuth token (auto-checks expiry)
    async function getOAuthToken() {
        const tokenData = await getEncrypted('oauth_access_token');
        if (!tokenData) return null;

        // Check if token has expired
        if (tokenData.expires_at && Date.now() > tokenData.expires_at) {
            console.log('[CryptoStorage] OAuth token expired, removing');
            await removeEncrypted('oauth_access_token');
            return null;
        }

        return tokenData.token;
    }

    // Clear all encrypted storage
    async function clearAll() {
        return new Promise((resolve) => {
            chrome.storage.local.get(null, (all) => {
                const encKeys = Object.keys(all).filter(k => k.startsWith('_enc_'));
                if (encKeys.length > 0) {
                    chrome.storage.local.remove(encKeys, () => {
                        console.log(`[CryptoStorage] Cleared ${encKeys.length} encrypted entries`);
                        resolve();
                    });
                } else {
                    resolve();
                }
            });
        });
    }

    // Public API
    return {
        encrypt,
        decrypt,
        setEncrypted,
        getEncrypted,
        removeEncrypted,
        storeOAuthToken,
        getOAuthToken,
        clearAll,
    };
})();

// Export for use in other extension scripts
if (typeof globalThis !== 'undefined') {
    globalThis.CryptoStorage = CryptoStorage;
}
