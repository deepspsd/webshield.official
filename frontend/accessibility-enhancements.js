/**
 * WebShield Accessibility Enhancement System
 * Provides comprehensive keyboard navigation and screen reader support
 */

class AccessibilityManager {
    constructor() {
        this.focusableElements = [
            'a[href]',
            'button:not([disabled])',
            'input:not([disabled])',
            'select:not([disabled])',
            'textarea:not([disabled])',
            '[tabindex]:not([tabindex="-1"])',
            '[contenteditable="true"]'
        ];
        
        this.skipLinks = [];
        this.announcements = [];
        
        this.init();
    }

    init() {
        this.addSkipLinks();
        this.enhanceKeyboardNavigation();
        this.addAriaLabels();
        this.setupFocusManagement();
        this.createAnnouncementRegion();
        this.addKeyboardShortcuts();
        this.enhanceFormAccessibility();
        this.setupReducedMotionSupport();
    }

    addSkipLinks() {
        const skipLinksContainer = document.createElement('div');
        skipLinksContainer.className = 'skip-links';
        skipLinksContainer.setAttribute('aria-label', 'Skip navigation links');
        
        const skipLinks = [
            { href: '#main-content', text: 'Skip to main content' },
            { href: '#navigation', text: 'Skip to navigation' },
            { href: '#footer', text: 'Skip to footer' }
        ];
        
        skipLinks.forEach(link => {
            const skipLink = document.createElement('a');
            skipLink.href = link.href;
            skipLink.textContent = link.text;
            skipLink.className = 'skip-link';
            skipLinksContainer.appendChild(skipLink);
        });
        
        document.body.insertBefore(skipLinksContainer, document.body.firstChild);
        
        this.addSkipLinkStyles();
    }

    addSkipLinkStyles() {
        if (document.getElementById('skip-link-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'skip-link-styles';
        style.textContent = `
            .skip-links {
                position: absolute;
                top: -100px;
                left: 0;
                z-index: 9999;
            }
            
            .skip-link {
                position: absolute;
                top: -100px;
                left: 8px;
                background: hsl(var(--primary));
                color: white;
                padding: 8px 16px;
                text-decoration: none;
                border-radius: 4px;
                font-weight: 600;
                transition: top 0.3s ease;
                border: 2px solid transparent;
            }
            
            .skip-link:focus {
                top: 8px;
                outline: 2px solid hsl(var(--accent));
                outline-offset: 2px;
            }
            
            .skip-link:hover {
                background: hsl(var(--primary-glow));
            }
        `;
        
        document.head.appendChild(style);
    }

    enhanceKeyboardNavigation() {
        // Add visible focus indicators
        this.addFocusStyles();
        
        // Handle tab navigation
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                this.handleTabNavigation(e);
            }
            
            // Escape key to close modals/dropdowns
            if (e.key === 'Escape') {
                this.handleEscapeKey();
            }
        });
        
        // Add focus trap for modals
        this.setupFocusTraps();
    }

    addFocusStyles() {
        if (document.getElementById('focus-styles')) return;
        
        const style = document.createElement('style');
        style.id = 'focus-styles';
        style.textContent = `
            /* Enhanced focus indicators */
            *:focus {
                outline: 2px solid hsl(var(--primary));
                outline-offset: 2px;
                border-radius: 4px;
            }
            
            button:focus,
            .btn:focus {
                outline: 3px solid hsl(var(--primary) / 0.7);
                outline-offset: 2px;
                box-shadow: 0 0 0 1px hsl(var(--background)), 0 0 8px hsl(var(--primary) / 0.4);
            }
            
            input:focus,
            textarea:focus,
            select:focus {
                outline: 2px solid hsl(var(--primary));
                outline-offset: 1px;
                border-color: hsl(var(--primary));
                box-shadow: 0 0 0 3px hsl(var(--primary) / 0.2);
            }
            
            a:focus {
                outline: 2px solid hsl(var(--primary));
                outline-offset: 2px;
                text-decoration: underline;
                text-decoration-thickness: 2px;
            }
            
            /* Focus within containers */
            .card:focus-within,
            .form-group:focus-within {
                box-shadow: 0 0 0 2px hsl(var(--primary) / 0.3);
                border-radius: var(--radius);
            }
            
            /* High contrast mode support */
            @media (prefers-contrast: high) {
                *:focus {
                    outline: 3px solid;
                    outline-offset: 3px;
                }
            }
        `;
        
        document.head.appendChild(style);
    }

    handleTabNavigation(e) {
        const focusableElements = document.querySelectorAll(this.focusableElements.join(', '));
        const firstElement = focusableElements[0];
        const lastElement = focusableElements[focusableElements.length - 1];
        
        // Trap focus within modals
        const activeModal = document.querySelector('.modal[aria-hidden="false"]');
        if (activeModal) {
            const modalFocusable = activeModal.querySelectorAll(this.focusableElements.join(', '));
            const firstModalElement = modalFocusable[0];
            const lastModalElement = modalFocusable[modalFocusable.length - 1];
            
            if (e.shiftKey && document.activeElement === firstModalElement) {
                e.preventDefault();
                lastModalElement.focus();
            } else if (!e.shiftKey && document.activeElement === lastModalElement) {
                e.preventDefault();
                firstModalElement.focus();
            }
        }
    }

    handleEscapeKey() {
        // Close any open modals
        const openModals = document.querySelectorAll('.modal[aria-hidden="false"]');
        openModals.forEach(modal => {
            modal.setAttribute('aria-hidden', 'true');
            modal.style.display = 'none';
        });
        
        // Close dropdowns
        const openDropdowns = document.querySelectorAll('.dropdown.open');
        openDropdowns.forEach(dropdown => {
            dropdown.classList.remove('open');
            dropdown.setAttribute('aria-expanded', 'false');
        });
    }

    setupFocusTraps() {
        // This will be enhanced when modals are detected
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1 && node.classList?.contains('modal')) {
                        this.setupModalFocusTrap(node);
                    }
                });
            });
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
    }

    setupModalFocusTrap(modal) {
        // Only move focus when the modal is actually open/visible.
        // Focusing a hidden modal during initial page parse can cause the page
        // to jump/scroll unexpectedly (e.g., on pages that include modals at the bottom).
        const ariaHidden = modal.getAttribute('aria-hidden');
        const style = window.getComputedStyle(modal);
        const isVisible = style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
        const isOpen = ariaHidden === 'false' || modal.classList.contains('open') || modal.dataset.open === 'true';

        if (!isVisible || !isOpen) return;

        const focusableElements = modal.querySelectorAll(this.focusableElements.join(', '));
        if (focusableElements.length > 0) {
            focusableElements[0].focus();
        }
    }

    addAriaLabels() {
        // Add ARIA labels to common elements
        this.enhanceButtons();
        this.enhanceLinks();
        this.enhanceImages();
        this.enhanceNavigation();
        this.enhanceForms();
    }

    enhanceButtons() {
        const buttons = document.querySelectorAll('button:not([aria-label]):not([aria-labelledby])');
        buttons.forEach(button => {
            if (!button.textContent.trim() && !button.getAttribute('aria-label')) {
                // Try to infer purpose from classes or context
                if (button.classList.contains('close')) {
                    button.setAttribute('aria-label', 'Close');
                } else if (button.classList.contains('menu')) {
                    button.setAttribute('aria-label', 'Open menu');
                } else if (button.querySelector('svg')) {
                    button.setAttribute('aria-label', 'Action button');
                }
            }
        });
    }

    enhanceLinks() {
        const links = document.querySelectorAll('a:not([aria-label]):not([aria-labelledby])');
        links.forEach(link => {
            // Add context for links that open in new windows
            if (link.target === '_blank' && !link.getAttribute('aria-label')) {
                const originalText = link.textContent.trim();
                link.setAttribute('aria-label', `${originalText} (opens in new window)`);
            }
            
            // Add rel="noopener" for security
            if (link.target === '_blank' && !link.rel.includes('noopener')) {
                link.rel = link.rel ? `${link.rel} noopener` : 'noopener';
            }
        });
    }

    enhanceImages() {
        const images = document.querySelectorAll('img:not([alt])');
        images.forEach(img => {
            // Add empty alt for decorative images
            if (img.classList.contains('decorative') || img.getAttribute('role') === 'presentation') {
                img.alt = '';
            } else {
                img.alt = 'Image';
            }
        });
    }

    enhanceNavigation() {
        const navElements = document.querySelectorAll('nav:not([aria-label]):not([aria-labelledby])');
        navElements.forEach((nav, index) => {
            nav.setAttribute('aria-label', `Navigation ${index + 1}`);
        });
        
        // Add landmarks
        const main = document.querySelector('main');
        if (main && !main.id) {
            main.id = 'main-content';
        }
        
        const header = document.querySelector('header, .header');
        if (header && !header.getAttribute('role')) {
            header.setAttribute('role', 'banner');
        }
        
        const footer = document.querySelector('footer, .footer');
        if (footer && !footer.getAttribute('role')) {
            footer.setAttribute('role', 'contentinfo');
        }
    }

    enhanceForms() {
        const forms = document.querySelectorAll('form');
        forms.forEach(form => {
            // Add form labels and descriptions
            const inputs = form.querySelectorAll('input, textarea, select');
            inputs.forEach(input => {
                if (!input.getAttribute('aria-label') && !input.getAttribute('aria-labelledby')) {
                    const label = form.querySelector(`label[for="${input.id}"]`);
                    if (!label && input.placeholder) {
                        input.setAttribute('aria-label', input.placeholder);
                    }
                }
                
                // Add required field indicators
                if (input.required && !input.getAttribute('aria-required')) {
                    input.setAttribute('aria-required', 'true');
                }
            });
        });
    }

    setupFocusManagement() {
        // Restore focus after page interactions
        let lastFocusedElement = null;
        
        document.addEventListener('focusin', (e) => {
            lastFocusedElement = e.target;
        });
        
        // Focus management for dynamic content
        window.addEventListener('popstate', () => {
            if (lastFocusedElement) {
                lastFocusedElement.focus();
            }
        });
    }

    createAnnouncementRegion() {
        const announcer = document.createElement('div');
        announcer.id = 'aria-announcer';
        announcer.setAttribute('aria-live', 'polite');
        announcer.setAttribute('aria-atomic', 'true');
        announcer.style.cssText = `
            position: absolute;
            left: -10000px;
            width: 1px;
            height: 1px;
            overflow: hidden;
        `;
        
        document.body.appendChild(announcer);
        
        // Create urgent announcer for important messages
        const urgentAnnouncer = document.createElement('div');
        urgentAnnouncer.id = 'aria-announcer-urgent';
        urgentAnnouncer.setAttribute('aria-live', 'assertive');
        urgentAnnouncer.setAttribute('aria-atomic', 'true');
        urgentAnnouncer.style.cssText = announcer.style.cssText;
        
        document.body.appendChild(urgentAnnouncer);
    }

    announce(message, urgent = false) {
        const announcer = document.getElementById(urgent ? 'aria-announcer-urgent' : 'aria-announcer');
        if (announcer) {
            announcer.textContent = message;
            
            // Clear after announcement
            setTimeout(() => {
                announcer.textContent = '';
            }, 1000);
        }
    }

    addKeyboardShortcuts() {
        const shortcuts = {
            'Alt+1': () => this.focusHeading(1),
            'Alt+2': () => this.focusHeading(2),
            'Alt+3': () => this.focusHeading(3),
            'Alt+M': () => this.focusMainContent(),
            'Alt+N': () => this.focusNavigation(),
            'Alt+S': () => this.focusSearch(),
            'Alt+/': () => this.showKeyboardHelp()
        };
        
        document.addEventListener('keydown', (e) => {
            const key = `${e.altKey ? 'Alt+' : ''}${e.ctrlKey ? 'Ctrl+' : ''}${e.shiftKey ? 'Shift+' : ''}${e.key}`;
            
            if (shortcuts[key]) {
                e.preventDefault();
                shortcuts[key]();
            }
        });
    }

    focusHeading(level) {
        const heading = document.querySelector(`h${level}`);
        if (heading) {
            heading.focus();
            this.announce(`Focused on ${heading.textContent}`);
        }
    }

    focusMainContent() {
        const main = document.querySelector('main, #main-content, [role="main"]');
        if (main) {
            main.focus();
            this.announce('Focused on main content');
        }
    }

    focusNavigation() {
        const nav = document.querySelector('nav, [role="navigation"]');
        if (nav) {
            const firstLink = nav.querySelector('a, button');
            if (firstLink) {
                firstLink.focus();
                this.announce('Focused on navigation');
            }
        }
    }

    focusSearch() {
        const search = document.querySelector('input[type="search"], input[name*="search"], #search');
        if (search) {
            search.focus();
            this.announce('Focused on search');
        }
    }

    showKeyboardHelp() {
        const helpText = `
            Keyboard shortcuts:
            Alt+1, Alt+2, Alt+3: Jump to headings
            Alt+M: Main content
            Alt+N: Navigation
            Alt+S: Search
            Tab: Next element
            Shift+Tab: Previous element
            Escape: Close dialogs
            Ctrl+Shift+T: Toggle theme
        `;
        
        this.announce(helpText, true);
    }

    enhanceFormAccessibility() {
        // Add live validation feedback
        const inputs = document.querySelectorAll('input, textarea, select');
        inputs.forEach(input => {
            input.addEventListener('invalid', (e) => {
                const message = e.target.validationMessage;
                this.announce(`Validation error: ${message}`, true);
            });
            
            input.addEventListener('input', (e) => {
                if (e.target.checkValidity()) {
                    e.target.setAttribute('aria-invalid', 'false');
                } else {
                    e.target.setAttribute('aria-invalid', 'true');
                }
            });
        });
    }

    setupReducedMotionSupport() {
        // Respect user's motion preferences
        const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
        
        const handleMotionPreference = (e) => {
            if (e.matches) {
                document.documentElement.style.setProperty('--animation-duration', '0.01ms');
                document.documentElement.style.setProperty('--transition-duration', '0.01ms');
                document.documentElement.classList.add('reduce-motion');
            } else {
                document.documentElement.style.removeProperty('--animation-duration');
                document.documentElement.style.removeProperty('--transition-duration');
                document.documentElement.classList.remove('reduce-motion');
            }
        };
        
        mediaQuery.addEventListener('change', handleMotionPreference);
        handleMotionPreference(mediaQuery);
    }

    // Public API methods
    setFocusTo(element) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (element) {
            element.focus();
            element.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    addLandmark(element, role, label) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (element) {
            element.setAttribute('role', role);
            if (label) {
                element.setAttribute('aria-label', label);
            }
        }
    }
}

// Initialize accessibility manager when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        window.accessibilityManager = new AccessibilityManager();
    });
} else {
    window.accessibilityManager = new AccessibilityManager();
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AccessibilityManager;
}
