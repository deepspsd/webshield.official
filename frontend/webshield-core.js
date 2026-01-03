// WebShield Core - Advanced Theme and Translation Management
(function() {
    'use strict';

    // Attach Bearer token automatically for API calls when strict auth is enabled.
    // This keeps existing pages working without changing every fetch call site.
    (function patchFetchForAuth() {
        if (window.__webshieldFetchPatched) return;
        window.__webshieldFetchPatched = true;

        const originalFetch = window.fetch.bind(window);

        window.fetch = async function(input, init) {
            try {
                const token = localStorage.getItem('accessToken');
                const url = typeof input === 'string' ? input : (input && input.url ? input.url : '');

                // Only attach token for /api requests (including API_BASE_URL-derived URLs).
                const shouldAttach = !!token && typeof url === 'string' && url.includes('/api/');
                if (!shouldAttach) {
                    return originalFetch(input, init);
                }

                const nextInit = init ? { ...init } : {};
                nextInit.headers = { ...(nextInit.headers || {}) };

                // Preserve any existing Authorization header.
                if (!('Authorization' in nextInit.headers) && !('authorization' in nextInit.headers)) {
                    nextInit.headers['Authorization'] = `Bearer ${token}`;
                }
                return originalFetch(input, nextInit);
            } catch (e) {
                return originalFetch(input, init);
            }
        };
    })();
    
    // Enhanced Global Theme Manager with Smooth Transitions
    const WebShieldTheme = {
        init() {
            console.log('🎨 WebShieldTheme.init() called');
            this.addThemeTransitions();
            const storedTheme = this.getStoredTheme();
            const systemTheme = this.getSystemTheme();
            const themeToUse = storedTheme || systemTheme;
            console.log('🎨 Theme to use:', themeToUse, 'stored:', storedTheme, 'system:', systemTheme);
            this.setTheme(themeToUse);
            this.setupEventListeners();
            this.createScrollProgress();
        },
        
        addThemeTransitions() {
            if (document.getElementById('theme-transitions')) return;
            
            const style = document.createElement('style');
            style.id = 'theme-transitions';
            style.textContent = `
                :root {
                    --transition-theme: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }
                
                * {
                    transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease, box-shadow 0.3s ease;
                }
                
                .theme-switching {
                    pointer-events: none;
                }
            `;
            document.head.appendChild(style);
        },
        
        createScrollProgress() {
            if (document.getElementById('scroll-progress')) return;
            
            const progress = document.createElement('div');
            progress.id = 'scroll-progress';
            progress.className = 'scroll-progress';
            document.body.appendChild(progress);
            
            window.addEventListener('scroll', () => {
                const scrolled = (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
                progress.style.width = Math.min(scrolled, 100) + '%';
            });
        },
        
        setTheme(theme) {
            document.body.classList.add('theme-switching');
            
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('webshield-theme', theme);
            
            // Update meta theme color with smooth transition
            const meta = document.querySelector('meta[name="theme-color"]');
            if (meta) {
                meta.content = theme === 'dark' ? 'hsl(224, 71%, 4%)' : 'hsl(0, 0%, 98%)';
            }
            
            // Broadcast theme change to other tabs/windows
            window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
            localStorage.setItem('webshield-theme-timestamp', Date.now().toString());
            
            this.updateThemeIcon();
            this.animateThemeChange(theme);
            
            setTimeout(() => {
                document.body.classList.remove('theme-switching');
            }, 300);
        },
        
        animateThemeChange(theme) {
            // Create a subtle flash effect for theme change feedback
            const flash = document.createElement('div');
            flash.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: ${theme === 'dark' ? 'rgba(0,0,0,0.1)' : 'rgba(255,255,255,0.1)'};
                pointer-events: none;
                z-index: 10000;
                opacity: 0;
                transition: opacity 0.15s ease;
            `;
            
            document.body.appendChild(flash);
            
            requestAnimationFrame(() => {
                flash.style.opacity = '1';
                setTimeout(() => {
                    flash.style.opacity = '0';
                    setTimeout(() => flash.remove(), 150);
                }, 50);
            });
        },
        
        toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            console.log('🎨 Toggling theme from', current, 'to', next);
            this.setTheme(next);
        },
        
        getCurrentTheme() {
            return document.documentElement.getAttribute('data-theme');
        },
        
        getStoredTheme() {
            return localStorage.getItem('webshield-theme');
        },
        
        getSystemTheme() {
            return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        },
        
        updateThemeIcon() {
            const btn = document.getElementById('theme-toggle');
            if (!btn) return;
            
            const isDark = this.getCurrentTheme() === 'dark';
            
            // Add rotation animation during icon change
            btn.style.transform = 'rotate(180deg)';
            
            setTimeout(() => {
                btn.innerHTML = isDark ? 
                    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>' :
                    '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
                btn.setAttribute('aria-label', isDark ? 'Switch to light theme' : 'Switch to dark theme');
                btn.style.transform = 'rotate(0deg)';
            }, 150);
        },
        
        createThemeToggle() {
            const headerActions = document.querySelector('.header-actions') || document.querySelector('.header-buttons');
            console.log('🎨 Creating theme toggle, headerActions found:', !!headerActions);
            if (!headerActions || document.getElementById('theme-toggle')) {
                console.log('🎨 Theme toggle creation skipped - headerActions:', !!headerActions, 'existing toggle:', !!document.getElementById('theme-toggle'));
                return;
            }
            
            const themeBtn = document.createElement('button');
            themeBtn.id = 'theme-toggle';
            themeBtn.className = 'theme-toggle-btn btn btn-ghost';
            themeBtn.setAttribute('aria-label', 'Toggle theme');
            themeBtn.setAttribute('title', 'Toggle dark/light theme');
            themeBtn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
            
            // Add ripple effect
            themeBtn.addEventListener('click', (e) => {
                console.log('🎨 Theme toggle button clicked');
                this.createRipple(e, themeBtn);
                this.toggleTheme();
            });
            
            headerActions.appendChild(themeBtn);
            console.log('🎨 Theme toggle button created and added to header');
            this.updateThemeIcon();
        },
        
        createRipple(event, element) {
            const ripple = document.createElement('span');
            const rect = element.getBoundingClientRect();
            const size = Math.max(rect.width, rect.height);
            const x = event.clientX - rect.left - size / 2;
            const y = event.clientY - rect.top - size / 2;
            
            ripple.style.cssText = `
                position: absolute;
                width: ${size}px;
                height: ${size}px;
                left: ${x}px;
                top: ${y}px;
                background: rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                transform: scale(0);
                animation: ripple 0.6s linear;
                pointer-events: none;
            `;
            
            element.style.position = 'relative';
            element.style.overflow = 'hidden';
            element.appendChild(ripple);
            
            setTimeout(() => ripple.remove(), 600);
        },
        
        setupEventListeners() {
            // Listen for theme changes from other tabs
            window.addEventListener('storage', (e) => {
                if (e.key === 'webshield-theme' && e.newValue) {
                    document.documentElement.setAttribute('data-theme', e.newValue);
                    this.updateThemeIcon();
                }
            });
            
            // Listen for system theme changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                if (!this.getStoredTheme()) {
                    this.setTheme(e.matches ? 'dark' : 'light');
                }
            });
            
            // Create theme toggle button when DOM is ready
            document.addEventListener('DOMContentLoaded', () => {
                setTimeout(() => this.createThemeToggle(), 100);
            });
        }
    };
    
    // Enhanced Global Language Manager with Full Page Translation
    const WebShieldLanguage = {
        supported: { 
            en: 'English', 
            es: 'Español', 
            fr: 'Français', 
            de: 'Deutsch', 
            pt: 'Português', 
            it: 'Italiano', 
            ja: '日本語', 
            ko: '한국어' 
        },
        
        current: localStorage.getItem('webshield-language') || 'en',
        originalTexts: new Map(),
        originalPlaceholders: new Map(),
        translationCache: {},
        
        init() {
            // Ensure English is default for fresh users
            if (!localStorage.getItem('webshield-language')) {
                localStorage.setItem('webshield-language', 'en');
                this.current = 'en';
            }
            
            this.setupEventListeners();
            
            // Delay UI creation to ensure DOM is ready
            setTimeout(() => {
                this.createUI();
                // Only translate if user has explicitly selected a non-English language
                if (this.current !== 'en' && localStorage.getItem('webshield-language-timestamp')) {
                    this.selectLanguage(this.current);
                } else {
                    this.updateButton();
                }
            }, 100);
        },
        
        createUI() {
            const headerActions = document.querySelector('.header-actions') || document.querySelector('.header-buttons');
            if (!headerActions || document.getElementById('translation-toggle')) return;
            
            const container = document.createElement('div');
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
                        ${Object.keys(this.supported).map(code => `
                            <button class="language-option ${code === this.current ? 'active' : ''}" data-lang="${code}">
                                <span class="lang-code">${code.toUpperCase()}</span>
                                <span class="lang-name">${this.supported[code]}</span>
                            </button>
                        `).join('')}
                    </div>
                </div>
            `;

            const themeBtn = headerActions.querySelector('.theme-toggle-btn');
            if (themeBtn) {
                headerActions.insertBefore(container, themeBtn);
            } else {
                headerActions.appendChild(container);
            }

            this.setupTranslationEventListeners();
        },
        
        setupTranslationEventListeners() {
            document.addEventListener('click', (e) => {
                const btn = e.target.closest('#translation-toggle');
                const opt = e.target.closest('.language-option');
                const sel = document.getElementById('language-selector');
                
                if (btn) {
                    e.preventDefault();
                    if (sel) sel.classList.toggle('hidden');
                } else if (opt) {
                    e.preventDefault();
                    this.selectLanguage(opt.getAttribute('data-lang'));
                    if (sel) sel.classList.add('hidden');
                } else if (sel && !sel.contains(e.target)) {
                    sel.classList.add('hidden');
                }
            });
        },
        
        setupEventListeners() {
            // Listen for language changes from other tabs
            window.addEventListener('storage', (e) => {
                if (e.key === 'webshield-language' && e.newValue && e.newValue !== this.current) {
                    this.current = e.newValue;
                    this.selectLanguage(this.current);
                }
            });
        },
        
        elementsToTranslate() {
            const elements = [];
            
            // Priority 1: Elements with data-translate attributes
            const dataTranslateElements = document.querySelectorAll('[data-translate]');
            dataTranslateElements.forEach(el => {
                const text = (el.textContent || '').trim();
                if (text && text.length >= 2) {
                    elements.push(el);
                }
            });
            
            // Priority 2: Content elements (excluding UI controls and navigation)
            const contentSelectors = [
                'h1:not(.no-translate h1):not(.translation-container h1)',
                'h2:not(.no-translate h2):not(.translation-container h2)', 
                'h3:not(.no-translate h3):not(.translation-container h3)',
                'h4:not(.no-translate h4):not(.translation-container h4)',
                'h5:not(.no-translate h5):not(.translation-container h5)',
                'h6:not(.no-translate h6):not(.translation-container h6)',
                'p:not(.no-translate p):not(.translation-container p)',
                'span:not(.logo-text):not(.lang-code):not(.translation-text):not(.icon):not(.no-translate span)',
                'label:not(.no-translate label)',
                'legend:not(.no-translate legend)',
                'li:not(.no-translate li):not(.translation-container li)'
            ];
            
            contentSelectors.forEach(selector => {
                try {
                    document.querySelectorAll(selector).forEach(el => {
                        const text = (el.textContent || '').trim();
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
            
            // Priority 3: Buttons (excluding UI controls)
            const buttons = document.querySelectorAll('button:not(.theme-toggle-btn):not(.translation-btn):not(.language-option):not(#mobile-menu-btn):not(.close-warning)');
            buttons.forEach(btn => {
                const text = (btn.textContent || '').trim();
                if (text && text.length >= 2 && !btn.closest('.translation-container') && !btn.closest('.no-translate')) {
                    if (elements.indexOf(btn) === -1) {
                        elements.push(btn);
                    }
                }
            });
            
            // Priority 4: Links (excluding navigation)
            const links = document.querySelectorAll('a:not(.logo):not([data-translate])');
            links.forEach(link => {
                const text = (link.textContent || '').trim();
                if (text && text.length >= 2 && !link.closest('.nav') && !link.closest('.no-translate')) {
                    if (elements.indexOf(link) === -1) {
                        elements.push(link);
                    }
                }
            });
            
            return elements;
        },
        
        storeOriginals(elems) {
            this.originalTexts.clear();
            this.originalPlaceholders.clear();
            
            elems.forEach(el => {
                const text = (el.textContent || '').trim();
                if (text) {
                    this.originalTexts.set(el, text);
                }
            });
            
            // Store original placeholders
            const placeholderElements = document.querySelectorAll('[placeholder]');
            placeholderElements.forEach(el => {
                const placeholder = el.getAttribute('placeholder');
                if (placeholder) {
                    this.originalPlaceholders.set(el, placeholder);
                }
            });
        },
        
        applyTranslations(elems, translationMap) {
            elems.forEach(el => {
                const originalText = this.originalTexts.get(el);
                if (originalText && translationMap[originalText]) {
                    const translation = translationMap[originalText];
                    if (translation !== originalText) {
                        el.textContent = translation;
                    }
                }
            });
            
            // Handle placeholder translations
            this.originalPlaceholders.forEach((originalPlaceholder, el) => {
                if (translationMap[originalPlaceholder]) {
                    const translation = translationMap[originalPlaceholder];
                    if (translation !== originalPlaceholder) {
                        el.setAttribute('placeholder', translation);
                    }
                }
            });
        },
        
        updateButton() {
            const btn = document.getElementById('translation-toggle');
            const text = btn ? btn.querySelector('.translation-text') : null;
            if (text) {
                text.textContent = (this.current === 'en') ? 'Translate' : (this.supported[this.current] || 'Translate');
            }
            
            // Update active language option
            const options = document.querySelectorAll('.language-option');
            options.forEach(opt => {
                opt.classList.toggle('active', opt.getAttribute('data-lang') === this.current);
            });
        },
        
        selectLanguage(code) {
            if (!this.supported[code]) return;
            
            this.current = code;
            localStorage.setItem('webshield-language', code);
            localStorage.setItem('webshield-language-timestamp', Date.now().toString());
            
            // Broadcast language change to other tabs/windows
            window.dispatchEvent(new CustomEvent('languageChanged', { detail: { language: code } }));
            
            if (code === 'en') {
                this.restore();
                this.updateButton();
                return;
            }
            
            // Check cache first
            const cacheKey = 'webshield-translations-' + code;
            const cached = localStorage.getItem(cacheKey);
            if (cached) {
                try {
                    const cachedData = JSON.parse(cached);
                    const elems = this.elementsToTranslate();
                    if (this.originalTexts.size === 0) this.storeOriginals(elems);
                    this.applyTranslations(elems, cachedData);
                    this.updateButton();
                    return;
                } catch(e) {
                    localStorage.removeItem(cacheKey);
                }
            }
            
            this.translatePage(code).then(() => {
                this.updateButton();
            }).catch(err => {
                console.error('Translation error:', err);
                if (!err.message.includes('API key') && !err.message.includes('Translation service unavailable')) {
                    this.showError(err.message);
                }
            });
        },
        
        restore() {
            this.originalTexts.forEach((originalText, el) => {
                el.textContent = originalText;
            });
            
            this.originalPlaceholders.forEach((originalPlaceholder, el) => {
                el.setAttribute('placeholder', originalPlaceholder);
            });
        },
        
        showError(message) {
            if (message && !message.includes('API key') && !message.includes('Translation service unavailable')) {
                const errorEl = document.createElement('div');
                errorEl.className = 'translation-error';
                errorEl.innerHTML = '<strong>Translation Error:</strong> ' + message;
                document.body.appendChild(errorEl);
                setTimeout(() => {
                    if (errorEl.parentNode) {
                        errorEl.remove();
                    }
                }, 4000);
            }
        },
        
        async translatePage(lang) {
            const elems = this.elementsToTranslate();
            if (!elems.length) return;
            
            if (this.originalTexts.size === 0) this.storeOriginals(elems);
            
            const textsToTranslate = [];
            this.originalTexts.forEach(text => {
                if (text && text.length < 500) {
                    textsToTranslate.push(text);
                }
            });
            
            // Add placeholders to translation
            this.originalPlaceholders.forEach(placeholder => {
                if (placeholder && placeholder.length < 500) {
                    textsToTranslate.push(placeholder);
                }
            });
            
            const btn = document.getElementById('translation-toggle');
            if (btn) btn.classList.add('translating');
            
            // Show progress indicator
            this.showProgressIndicator();
            
            try {
                const startTime = Date.now();
                const response = await fetch('/api/translations/translate/batch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        texts: textsToTranslate, 
                        target_lang: lang, 
                        context: 'web interface' 
                    })
                });
                
                const processingTime = Date.now() - startTime;
                
                if (!response.ok) {
                    if (response.status === 500) {
                        console.info('Using fallback translations (Gemini API not configured)');
                        this.showInfo('Using offline translations');
                        return { translations: {} };
                    }
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                const translations = data.translations || {};
                
                // Apply translations with smooth animation
                await this.applyTranslationsWithAnimation(elems, translations);
                
                // Cache translations for faster loading
                const cacheKey = 'webshield-translations-' + lang;
                localStorage.setItem(cacheKey, JSON.stringify(translations));
                
                // Show success feedback
                if (data.success !== false) {
                    this.showSuccess(`Page translated to ${this.supported[lang]} (${processingTime}ms)`);
                }
                
            } catch (err) {
                console.error('Translation error:', err);
                this.showError(`Translation failed: ${err.message}`);
            } finally {
                if (btn) btn.classList.remove('translating');
                this.hideProgressIndicator();
            }
        },

        async applyTranslationsWithAnimation(elems, translationMap) {
            // Apply translations with staggered animation
            const promises = elems.map((el, index) => {
                return new Promise(resolve => {
                    setTimeout(() => {
                        const originalText = this.originalTexts.get(el);
                        if (originalText && translationMap[originalText]) {
                            const translation = translationMap[originalText];
                            if (translation !== originalText) {
                                // Add fade effect
                                el.style.transition = 'opacity 0.2s ease';
                                el.style.opacity = '0.7';
                                
                                setTimeout(() => {
                                    el.textContent = translation;
                                    el.style.opacity = '1';
                                    resolve();
                                }, 100);
                            } else {
                                resolve();
                            }
                        } else {
                            resolve();
                        }
                    }, index * 10); // Stagger by 10ms
                });
            });
            
            await Promise.all(promises);
        },

        showProgressIndicator() {
            if (document.getElementById('translation-progress')) return;
            
            const progress = document.createElement('div');
            progress.id = 'translation-progress';
            progress.className = 'translation-progress';
            progress.innerHTML = `
                <div class="progress-spinner"></div>
                <span>Translating...</span>
            `;
            document.body.appendChild(progress);
        },

        hideProgressIndicator() {
            const progress = document.getElementById('translation-progress');
            if (progress) {
                progress.remove();
            }
        },

        showSuccess(message) {
            this.showNotification(message, 'success');
        },

        showInfo(message) {
            this.showNotification(message, 'info');
        },

        showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = `translation-notification translation-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <span class="notification-icon">${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}</span>
                    <span class="notification-message">${message}</span>
                </div>
            `;
            
            document.body.appendChild(notification);
            
            // Auto remove after 3 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.style.opacity = '0';
                    setTimeout(() => notification.remove(), 300);
                }
            }, 3000);
        },
        
        // Public API
        setLanguage: function(code) { return this.selectLanguage(code); },
        getCurrentLanguage: function() { return this.current; },
        getSupportedLanguages: function() { return this.supported; }
    };
    
    // Global API
    window.WebShieldTheme = WebShieldTheme;
    window.WebShieldLanguage = WebShieldLanguage;
    
    // Add CSS styles for translation and theme UI
    const addStyles = () => {
        if (document.getElementById('webshield-core-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'webshield-core-styles';
        style.textContent = `
            /* Ripple Animation */
            @keyframes ripple {
                to {
                    transform: scale(4);
                    opacity: 0;
                }
            }
            
            /* Scroll Progress Bar */
            .scroll-progress {
                position: fixed;
                top: 0;
                left: 0;
                width: 0%;
                height: 3px;
                background: linear-gradient(90deg, hsl(var(--primary)), hsl(var(--accent)), hsl(var(--primary)));
                background-size: 200% 100%;
                z-index: 10000;
                transition: width 0.1s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 2px 8px hsl(var(--primary) / 0.3);
                animation: shimmer 3s ease-in-out infinite;
            }
            
            @keyframes shimmer {
                0% { background-position: -200% 0; }
                100% { background-position: 200% 0; }
            }
            
            /* Enhanced Theme Toggle Button */
            .theme-toggle-btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 44px;
                height: 44px;
                border-radius: 12px;
                background: hsl(var(--card));
                border: 1px solid hsl(var(--border));
                color: hsl(var(--foreground));
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 2px 8px hsl(var(--background) / 0.1);
                position: relative;
                overflow: hidden;
            }
            
            .theme-toggle-btn:hover {
                background: hsl(var(--muted));
                border-color: hsl(var(--primary));
                transform: translateY(-2px) scale(1.05);
                box-shadow: 0 8px 25px hsl(var(--primary) / 0.2);
            }
            
            .theme-toggle-btn:active {
                transform: translateY(0) scale(0.98);
            }
            
            .theme-toggle-btn svg {
                transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            /* Enhanced Translation Container */
            .translation-container {
                position: relative;
                display: inline-flex;
                align-items: center;
                margin-right: 0.75rem;
            }
            
            .translation-btn {
                display: inline-flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.6rem 1rem;
                background: hsl(var(--card));
                border: 1px solid hsl(var(--border));
                border-radius: 12px;
                color: hsl(var(--foreground));
                font-size: 0.875rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 2px 8px hsl(var(--background) / 0.1);
                position: relative;
                overflow: hidden;
            }
            
            .translation-btn:hover {
                background: hsl(var(--muted));
                border-color: hsl(var(--primary));
                transform: translateY(-2px) scale(1.02);
                box-shadow: 0 8px 25px hsl(var(--primary) / 0.15);
            }
            
            .translation-btn:active {
                transform: translateY(0) scale(0.98);
            }
            
            .translation-btn.translating {
                opacity: 0.7;
                cursor: not-allowed;
                animation: pulse 1.5s ease-in-out infinite;
            }
            
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.02); }
            }
            
            .translation-btn svg {
                transition: transform 0.3s ease;
            }
            
            .translation-btn:hover svg {
                transform: rotate(15deg) scale(1.1);
            }
            
            /* Enhanced Language Selector */
            .language-selector {
                position: absolute;
                top: calc(100% + 8px);
                right: 0;
                background: hsl(var(--card));
                border: 1px solid hsl(var(--border));
                border-radius: 16px;
                box-shadow: 0 20px 40px -10px hsl(var(--background) / 0.3), 0 0 0 1px hsl(var(--border) / 0.1);
                z-index: 1000;
                min-width: 220px;
                backdrop-filter: blur(20px);
                transform: translateY(-10px) scale(0.95);
                opacity: 0;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                pointer-events: none;
            }
            
            .language-selector:not(.hidden) {
                transform: translateY(0) scale(1);
                opacity: 1;
                pointer-events: all;
            }
            
            .language-selector.hidden {
                display: none;
            }
            
            .language-list {
                padding: 0.75rem;
                max-height: 320px;
                overflow-y: auto;
            }
            
            .language-option {
                display: flex;
                align-items: center;
                justify-content: space-between;
                width: 100%;
                padding: 0.75rem 1rem;
                background: transparent;
                border: none;
                border-radius: 10px;
                color: hsl(var(--foreground));
                font-size: 0.875rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
            }
            
            .language-option:hover {
                background: hsl(var(--muted));
                transform: translateX(4px);
            }
            
            .language-option.active {
                background: linear-gradient(135deg, hsl(var(--primary) / 0.1), hsl(var(--accent) / 0.1));
                color: hsl(var(--primary));
                font-weight: 600;
                border: 1px solid hsl(var(--primary) / 0.2);
            }
            
            .language-option.active::before {
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                width: 3px;
                height: 100%;
                background: linear-gradient(135deg, hsl(var(--primary)), hsl(var(--accent)));
                border-radius: 0 2px 2px 0;
            }
            
            .lang-code {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 36px;
                height: 24px;
                background: hsl(var(--muted) / 0.5);
                border-radius: 6px;
                font-weight: 700;
                font-size: 0.75rem;
                color: hsl(var(--muted-foreground));
                transition: all 0.3s ease;
            }
            
            .language-option:hover .lang-code {
                background: hsl(var(--primary) / 0.2);
                color: hsl(var(--primary));
                transform: scale(1.1);
            }
            
            .language-option.active .lang-code {
                background: hsl(var(--primary));
                color: hsl(var(--primary-foreground));
                box-shadow: 0 2px 8px hsl(var(--primary) / 0.3);
            }
            
            .lang-name {
                font-weight: 500;
                flex: 1;
                text-align: left;
                margin-left: 0.75rem;
            }
            
            /* Enhanced Translation Notifications */
            .translation-notification {
                position: fixed;
                top: 80px;
                right: 20px;
                padding: 16px 24px;
                border-radius: 12px;
                box-shadow: 0 10px 30px hsl(var(--background) / 0.3);
                z-index: 10000;
                max-width: 420px;
                backdrop-filter: blur(10px);
                border: 1px solid hsl(var(--border) / 0.2);
                animation: slideInRight 0.4s cubic-bezier(0.4, 0, 0.2, 1);
                font-weight: 500;
                transition: opacity 0.3s ease;
            }

            .translation-success {
                background: linear-gradient(135deg, hsl(var(--success)), hsl(var(--success) / 0.8));
                color: white;
                border-color: hsl(var(--success) / 0.2);
            }

            .translation-error {
                background: linear-gradient(135deg, hsl(var(--destructive)), hsl(var(--destructive) / 0.8));
                color: white;
                border-color: hsl(var(--destructive) / 0.2);
            }

            .translation-info {
                background: linear-gradient(135deg, hsl(var(--info)), hsl(var(--info) / 0.8));
                color: white;
                border-color: hsl(var(--info) / 0.2);
            }

            .notification-content {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .notification-icon {
                font-size: 18px;
                font-weight: bold;
            }

            .notification-message {
                flex: 1;
            }

            /* Translation Progress Indicator */
            .translation-progress {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: hsl(var(--card));
                border: 1px solid hsl(var(--border));
                border-radius: 16px;
                padding: 24px 32px;
                box-shadow: var(--shadow-xl);
                z-index: 10001;
                backdrop-filter: blur(20px);
                display: flex;
                align-items: center;
                gap: 16px;
                animation: scaleIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }

            .progress-spinner {
                width: 24px;
                height: 24px;
                border: 3px solid hsl(var(--border));
                border-top: 3px solid hsl(var(--primary));
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }

            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }

            @keyframes scaleIn {
                from { 
                    opacity: 0;
                    transform: translate(-50%, -50%) scale(0.9);
                }
                to { 
                    opacity: 1;
                    transform: translate(-50%, -50%) scale(1);
                }
            }
            
            @keyframes slideInRight {
                from { 
                    transform: translateX(100%) scale(0.9); 
                    opacity: 0;
                }
                to { 
                    transform: translateX(0) scale(1); 
                    opacity: 1;
                }
            }
            
            /* Mobile and responsive adjustments */
            @media (max-width: 768px) {
                .translation-container {
                    margin-right: 0.5rem;
                }
                
                .translation-btn {
                    padding: 0.5rem 0.75rem;
                    font-size: 0.8rem;
                }
                
                .translation-text {
                    display: none;
                }
                
                .theme-toggle-btn {
                    width: 40px;
                    height: 40px;
                }
                
                .language-selector {
                    right: -20px;
                    min-width: 200px;
                    max-width: calc(100vw - 40px);
                }
                
                .scroll-progress {
                    height: 2px;
                }
                
                .translation-error {
                    right: 10px;
                    left: 10px;
                    max-width: none;
                }
            }
            
            /* Reduced motion preferences */
            @media (prefers-reduced-motion: reduce) {
                .theme-toggle-btn,
                .translation-btn,
                .language-option {
                    transition: none;
                }
                
                .theme-toggle-btn:hover,
                .translation-btn:hover {
                    transform: none;
                }
                
                .scroll-progress {
                    animation: none;
                }
                
                .translation-btn.translating {
                    animation: none;
                }
            }
        `;
        
        // Add additional utility styles
        style.textContent += `
            /* Utility Classes */
            .fade-in {
                animation: fadeIn 0.6s ease-out;
            }
            
            .slide-up {
                animation: slideUp 0.6s ease-out;
            }
            
            .scale-in {
                animation: scaleIn 0.4s ease-out;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
            
            @keyframes slideUp {
                from { 
                    opacity: 0;
                    transform: translateY(20px);
                }
                to { 
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            @keyframes scaleIn {
                from { 
                    opacity: 0;
                    transform: scale(0.9);
                }
                to { 
                    opacity: 1;
                    transform: scale(1);
                }
            }
        `;
        
        document.head.appendChild(style);
    };
    
    // Auto-initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', () => {
        addStyles();
        WebShieldTheme.init();
        WebShieldLanguage.init();
    });
    
})();

