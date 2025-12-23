// WebShield Translation System - Centralized and Optimized
(function() {
    'use strict';
    
    var supported = { 
        en: 'English', 
        es: 'Español', 
        fr: 'Français', 
        de: 'Deutsch', 
        pt: 'Português', 
        it: 'Italiano', 
        ja: '日本語', 
        ko: '한국어' 
    };
    
    var current = localStorage.getItem('webshield-language') || 'en';
    var originalTexts = new Map();
    var originalPlaceholders = new Map();
    var translationCache = {};

    // Ensure English is always the default for fresh users
    if (!localStorage.getItem('webshield-language')) {
        localStorage.setItem('webshield-language', 'en');
        current = 'en';
    }

    function createUI() {
        var headerActions = document.querySelector('.header-actions') || document.querySelector('.header-buttons');
        if (!headerActions || document.getElementById('translation-toggle')) return;
        
        var container = document.createElement('div');
        container.className = 'translation-container';
        container.innerHTML = `
            <button id="translation-toggle" class="translation-btn" title="Translate Page">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12.87 15.07l-2.54-2.51.03-.03c1.74-1.94 2.98-4.17 3.71-6.53H17V4h-7V2H8v2H1v1.99h11.17C11.5 7.92 10.44 9.75 9 11.35 8.07 10.32 7.3 9.19 6.69 8h-2c.73 1.63 1.73 3.17 2.98 4.56l-5.09 5.02L4 19l5-5 3.11 3.11.76-2.04zM18.5 10h-2L12 22h2l1.12-3h4.75L21 22h2l-4.5-12zm-2.62 7l1.62-4.33L19.12 17h-3.24z"/>
                </svg>
                <span class="translation-text">Translate</span>
            </button>
            <div id="language-selector" class="language-selector hidden">
                <div class="language-list">
                    ${Object.keys(supported).map(code => `
                        <button class="language-option ${code === current ? 'active' : ''}" data-lang="${code}">
                            <span class="lang-code">${code.toUpperCase()}</span>
                            <span class="lang-name">${supported[code]}</span>
                        </button>
                    `).join('')}
                </div>
            </div>
        `;

        var themeBtn = headerActions.querySelector('.theme-toggle-btn');
        if (themeBtn) {
            headerActions.insertBefore(container, themeBtn);
        } else {
            headerActions.appendChild(container);
        }

        // Event listeners
        document.addEventListener('click', function(e) {
            var btn = e.target.closest('#translation-toggle');
            var opt = e.target.closest('.language-option');
            var sel = document.getElementById('language-selector');
            
            if (btn) {
                e.preventDefault();
                if (sel) sel.classList.toggle('hidden');
            } else if (opt) {
                e.preventDefault();
                selectLanguage(opt.getAttribute('data-lang'));
                if (sel) sel.classList.add('hidden');
            } else if (sel && !sel.contains(e.target)) {
                sel.classList.add('hidden');
            }
        });
    }

    function elementsToTranslate() {
        var elements = [];
        
        // Get elements with data-translate attributes (highest priority)
        var dataTranslateElements = document.querySelectorAll('[data-translate]');
        dataTranslateElements.forEach(function(el) {
            var text = (el.textContent || '').trim();
            if (text && text.length >= 2) {
                elements.push(el);
            }
        });
        
        // Get content elements (excluding navigation and UI controls)
        var contentSelectors = [
            'h1:not(.no-translate h1):not(.translation-container h1)',
            'h2:not(.no-translate h2):not(.translation-container h2)', 
            'h3:not(.no-translate h3):not(.translation-container h3)',
            'h4:not(.no-translate h4):not(.translation-container h4)',
            'h5:not(.no-translate h5):not(.translation-container h5)',
            'h6:not(.no-translate h6):not(.translation-container h6)',
            'p:not(.no-translate p):not(.translation-container p)',
            'span:not(.logo-text):not(.lang-code):not(.translation-text):not(.icon):not(.no-translate span)',
            'label:not(.no-translate label)',
            'legend:not(.no-translate legend)'
        ];
        
        contentSelectors.forEach(function(selector) {
            try {
                document.querySelectorAll(selector).forEach(function(el) {
                    var text = (el.textContent || '').trim();
                    if (!text || text.length < 2) return;
                    if (el.closest('.no-translate')) return;
                    if (el.closest('.translation-container')) return;
                    if (el.offsetParent === null && !el.matches('input')) return;
                    if (elements.indexOf(el) === -1) {
                        elements.push(el);
                    }
                });
            } catch(e) {
                console.warn('Translation selector error:', selector, e);
            }
        });
        
        // Handle buttons (excluding UI controls)
        var buttons = document.querySelectorAll('button:not(.theme-toggle-btn):not(.translation-btn):not(.language-option):not(#mobile-menu-btn):not(.close-warning)');
        buttons.forEach(function(btn) {
            var text = (btn.textContent || '').trim();
            if (text && text.length >= 2 && !btn.closest('.translation-container') && !btn.closest('.no-translate')) {
                if (elements.indexOf(btn) === -1) {
                    elements.push(btn);
                }
            }
        });
        
        // Handle links (excluding navigation)
        var links = document.querySelectorAll('a:not(.logo):not([data-translate])');
        links.forEach(function(link) {
            var text = (link.textContent || '').trim();
            if (text && text.length >= 2 && !link.closest('.nav') && !link.closest('.no-translate')) {
                if (elements.indexOf(link) === -1) {
                    elements.push(link);
                }
            }
        });
        
        return elements;
    }

    function storeOriginals(elems) {
        originalTexts.clear();
        originalPlaceholders.clear();
        
        elems.forEach(function(el) {
            var text = (el.textContent || '').trim();
            if (text) {
                originalTexts.set(el, text);
            }
        });
        
        // Store original placeholders
        var placeholderElements = document.querySelectorAll('[placeholder]');
        placeholderElements.forEach(function(el) {
            var placeholder = el.getAttribute('placeholder');
            if (placeholder) {
                originalPlaceholders.set(el, placeholder);
            }
        });
    }

    function applyTranslations(elems, translationMap) {
        elems.forEach(function(el) {
            var originalText = originalTexts.get(el);
            if (originalText && translationMap[originalText]) {
                var translation = translationMap[originalText];
                if (translation !== originalText) {
                    el.textContent = translation;
                }
            }
        });
        
        // Handle placeholder translations
        originalPlaceholders.forEach(function(originalPlaceholder, el) {
            if (translationMap[originalPlaceholder]) {
                var translation = translationMap[originalPlaceholder];
                if (translation !== originalPlaceholder) {
                    el.setAttribute('placeholder', translation);
                }
            }
        });
    }

    function updateButton() {
        var btn = document.getElementById('translation-toggle');
        var text = btn ? btn.querySelector('.translation-text') : null;
        if (text) {
            text.textContent = (current === 'en') ? 'Translate' : (supported[current] || 'Translate');
        }
        
        // Update active language option
        var options = document.querySelectorAll('.language-option');
        options.forEach(function(opt) {
            opt.classList.toggle('active', opt.getAttribute('data-lang') === current);
        });
    }

    function selectLanguage(code) {
        if (!supported[code]) return;
        
        current = code;
        localStorage.setItem('webshield-language', code);
        localStorage.setItem('webshield-language-timestamp', Date.now().toString());
        
        // Broadcast language change to other tabs/windows
        window.dispatchEvent(new CustomEvent('languageChanged', { detail: { language: code } }));
        
        if (code === 'en') {
            restore();
            updateButton();
            return;
        }
        
        // Check cache first
        var cacheKey = 'webshield-translations-' + code;
        var cached = localStorage.getItem(cacheKey);
        if (cached) {
            try {
                var cachedData = JSON.parse(cached);
                var elems = elementsToTranslate();
                if (originalTexts.size === 0) storeOriginals(elems);
                applyTranslations(elems, cachedData);
                updateButton();
                return;
            } catch(e) {
                localStorage.removeItem(cacheKey);
            }
        }
        
        translatePage(code).then(function() {
            updateButton();
        }).catch(function(err) {
            console.error('Translation error:', err);
            if (!err.message.includes('API key') && !err.message.includes('Translation service unavailable')) {
                showError(err.message);
            }
        });
    }

    function restore() {
        originalTexts.forEach(function(originalText, el) {
            el.textContent = originalText;
        });
        
        originalPlaceholders.forEach(function(originalPlaceholder, el) {
            el.setAttribute('placeholder', originalPlaceholder);
        });
    }

    function showError(message) {
        if (message && !message.includes('API key') && !message.includes('Translation service unavailable')) {
            var errorEl = document.createElement('div');
            errorEl.className = 'translation-error';
            errorEl.innerHTML = '<strong>Translation Error:</strong> ' + message;
            document.body.appendChild(errorEl);
            setTimeout(function() {
                if (errorEl.parentNode) {
                    errorEl.remove();
                }
            }, 4000);
        }
    }

    function translatePage(lang) {
        var elems = elementsToTranslate();
        if (!elems.length) return Promise.resolve();
        
        if (originalTexts.size === 0) storeOriginals(elems);
        
        var textsToTranslate = [];
        originalTexts.forEach(function(text) {
            if (text && text.length < 500) {
                textsToTranslate.push(text);
            }
        });
        
        // Add placeholders to translation
        originalPlaceholders.forEach(function(placeholder) {
            if (placeholder && placeholder.length < 500) {
                textsToTranslate.push(placeholder);
            }
        });
        
        var btn = document.getElementById('translation-toggle');
        if (btn) btn.classList.add('translating');
        
        return fetch('/api/translations/translate/batch', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                texts: textsToTranslate, 
                target_lang: lang, 
                context: 'web interface' 
            })
        })
        .then(function(res) {
            if (!res.ok) {
                if (res.status === 500) {
                    console.info('Using fallback translations (Gemini API not configured)');
                    return { translations: {} };
                }
                throw new Error('HTTP ' + res.status);
            }
            return res.json();
        })
        .then(function(data) {
            var translations = data.translations || {};
            applyTranslations(elems, translations);
            
            // Cache translations for faster loading
            var cacheKey = 'webshield-translations-' + lang;
            localStorage.setItem(cacheKey, JSON.stringify(translations));
        })
        .catch(function(err) {
            console.error('Translation error:', err);
            if (!err.message.includes('API key') && !err.message.includes('Translation service unavailable')) {
                showError(err.message);
            }
        })
        .finally(function() {
            if (btn) btn.classList.remove('translating');
        });
    }

    // Global language manager
    window.WebShieldLanguage = {
        setLanguage: selectLanguage,
        getCurrentLanguage: function() { return current; },
        getSupportedLanguages: function() { return supported; },
        init: function() {
            // Listen for language changes from other tabs
            window.addEventListener('storage', function(e) {
                if (e.key === 'webshield-language' && e.newValue && e.newValue !== current) {
                    current = e.newValue;
                    selectLanguage(current);
                }
            });
        }
    };
    
    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        setTimeout(function() {
            createUI();
            window.WebShieldLanguage.init();
            // Only translate if user has explicitly selected a non-English language
            if (current !== 'en' && localStorage.getItem('webshield-language-timestamp')) {
                selectLanguage(current);
            } else {
                updateButton();
            }
        }, 100);
    });
})();
