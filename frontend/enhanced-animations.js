// Enhanced WebShield UI Animations - Shared across all pages

// Enhanced scroll animations and intersection observer
function initScrollAnimations() {
    const observerOptions = {
        threshold: [0.1, 0.3, 0.5, 0.7, 0.9],
        rootMargin: '0px 0px -100px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const element = entry.target;
                const ratio = entry.intersectionRatio;
                
                // Staggered animation based on intersection ratio
                element.style.opacity = Math.min(1, ratio * 2);
                element.style.transform = `translateY(${Math.max(0, 30 * (1 - ratio))}px) scale(${0.95 + (ratio * 0.05)})`;
                element.classList.add('animate-in');
                
                // Add special effects for different elements
                if (element.classList.contains('feature-card') || element.classList.contains('enhanced-analysis-card')) {
                    element.style.animationDelay = `${Math.random() * 0.3}s`;
                    element.style.animation = 'slideInFromBottom 0.8s ease-out forwards';
                }
                
                if (element.classList.contains('recent-scan-card')) {
                    element.style.animation = 'fadeInUp 0.6s ease-out forwards';
                }
                
                if (element.classList.contains('enhanced-stat-card')) {
                    element.style.animation = 'slideInFromBottom 0.6s ease-out forwards';
                }
            } else {
                // Reset animation when out of view
                entry.target.style.opacity = '0';
                entry.target.style.transform = 'translateY(30px) scale(0.95)';
                entry.target.classList.remove('animate-in');
            }
        });
    }, observerOptions);

    // Observe all animated elements with enhanced selectors
    const animatedElements = document.querySelectorAll(`
        .feature-card, 
        .recent-scan-card, 
        .analysis-card,
        .enhanced-analysis-card,
        .enhanced-stat-card,
        .hero-content,
        .features-header,
        .recent-scans-header,
        .extension-content,
        .footer-grid > div,
        .enhanced-header,
        .enhanced-title,
        .enhanced-status-badge,
        .enhanced-url-display,
        .enhanced-stats-grid,
        .enhanced-analysis-section
    `);
    
    animatedElements.forEach((el, index) => {
        // Add initial state
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px) scale(0.95)';
        el.style.transition = 'all 0.8s cubic-bezier(0.4, 0, 0.2, 1)';
        
        // Stagger the observation
        setTimeout(() => {
            observer.observe(el);
        }, index * 100);
    });
}

// Smooth scroll for anchor links
function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Enhanced button interactions
function initButtonAnimations() {
    document.querySelectorAll('.btn, .enhanced-back-button').forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px) scale(1.02)';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
        
        btn.addEventListener('mousedown', function() {
            this.style.transform = 'translateY(1px) scale(0.98)';
        });
        
        btn.addEventListener('mouseup', function() {
            this.style.transform = 'translateY(-2px) scale(1.02)';
        });
    });
}

// Enhanced parallax effect for hero section and other elements
function initParallaxEffect() {
    const hero = document.querySelector('.hero');
    const heroBg = document.querySelector('.hero-bg');
    const features = document.querySelector('.features');
    const extension = document.querySelector('.extension-cta');
    
    let ticking = false;
    
    function updateParallax() {
        const scrolled = window.pageYOffset;
        const windowHeight = window.innerHeight;
        
        // Hero parallax with multiple layers
        if (hero) {
            const heroRate = scrolled * -0.3;
            hero.style.transform = `translateY(${heroRate}px)`;
        }
        
        if (heroBg) {
            const bgRate = scrolled * -0.1;
            heroBg.style.transform = `translateY(${bgRate}px)`;
        }
        
        // Features section parallax
        if (features) {
            const featuresRect = features.getBoundingClientRect();
            if (featuresRect.top < windowHeight && featuresRect.bottom > 0) {
                const featuresRate = (windowHeight - featuresRect.top) * 0.1;
                features.style.transform = `translateY(${featuresRate}px)`;
            }
        }
        
        // Extension section parallax
        if (extension) {
            const extensionRect = extension.getBoundingClientRect();
            if (extensionRect.top < windowHeight && extensionRect.bottom > 0) {
                const extensionRate = (windowHeight - extensionRect.top) * -0.05;
                extension.style.transform = `translateY(${extensionRate}px)`;
            }
        }
        
        ticking = false;
    }
    
    function requestTick() {
        if (!ticking) {
            requestAnimationFrame(updateParallax);
            ticking = true;
        }
    }
    
    window.addEventListener('scroll', requestTick, { passive: true });
}

// Enhanced scroll progress indicator with smooth performance
function initScrollProgress() {
    // Create progress bar
    if (document.querySelector('.scroll-progress')) {
        return;
    }
    const progressBar = document.createElement('div');
    progressBar.className = 'scroll-progress';
    document.body.appendChild(progressBar);

    let ticking = false;
    
    function updateProgress() {
        const scrollTop = window.pageYOffset;
        const docHeight = document.documentElement.scrollHeight - window.innerHeight;
        const scrollPercent = Math.min(100, Math.max(0, (scrollTop / docHeight) * 100));
        
        // Smooth progress update with easing
        progressBar.style.width = scrollPercent + '%';
        
        // Add glow effect when scrolling fast
        if (scrollPercent > 80) {
            progressBar.style.boxShadow = '0 2px 12px hsl(var(--primary) / 0.6)';
        } else {
            progressBar.style.boxShadow = '0 2px 8px hsl(var(--primary) / 0.3)';
        }
        
        ticking = false;
    }
    
    function requestTick() {
        if (!ticking) {
            requestAnimationFrame(updateProgress);
            ticking = true;
        }
    }

    // Update progress on scroll with throttling
    window.addEventListener('scroll', requestTick, { passive: true });
    
    // Add scroll-to-top button when scrolled down
    let scrollToTopBtn = null;
    
    function toggleScrollToTop() {
        const scrollTop = window.pageYOffset;
        
        if (scrollTop > 300 && !scrollToTopBtn) {
            scrollToTopBtn = document.createElement('button');
            scrollToTopBtn.innerHTML = '↑';
            scrollToTopBtn.className = 'scroll-to-top';
            scrollToTopBtn.style.cssText = `
                position: fixed;
                bottom: 2rem;
                right: 2rem;
                width: 50px;
                height: 50px;
                border-radius: 50%;
                background: linear-gradient(135deg, hsl(var(--primary)), hsl(var(--accent)));
                color: white;
                border: none;
                font-size: 1.5rem;
                cursor: pointer;
                z-index: 1000;
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                box-shadow: 0 4px 15px hsl(var(--primary) / 0.3);
            `;
            
            scrollToTopBtn.addEventListener('click', () => {
                window.scrollTo({
                    top: 0,
                    behavior: 'smooth'
                });
            });
            
            document.body.appendChild(scrollToTopBtn);
            
            // Animate in
            setTimeout(() => {
                scrollToTopBtn.style.opacity = '1';
                scrollToTopBtn.style.transform = 'translateY(0)';
            }, 100);
        } else if (scrollTop <= 300 && scrollToTopBtn) {
            scrollToTopBtn.style.opacity = '0';
            scrollToTopBtn.style.transform = 'translateY(20px)';
            setTimeout(() => {
                if (scrollToTopBtn) {
                    scrollToTopBtn.remove();
                    scrollToTopBtn = null;
                }
            }, 300);
        }
    }
    
    window.addEventListener('scroll', toggleScrollToTop, { passive: true });
}

// Enhanced mobile menu functionality
function initMobileMenu() {
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    const mobileNav = document.getElementById('mobile-nav');
    
    if (mobileMenuBtn && mobileNav) {
        mobileMenuBtn.addEventListener('click', () => {
            mobileNav.classList.toggle('active');
        });
        
        // Close mobile menu when clicking on a link
        const navLinks = mobileNav.querySelectorAll('a');
        navLinks.forEach(link => {
            link.addEventListener('click', () => {
                mobileNav.classList.remove('active');
            });
        });
        
        // Close mobile menu when clicking outside
        document.addEventListener('click', (e) => {
            if (!mobileMenuBtn.contains(e.target) && !mobileNav.contains(e.target)) {
                mobileNav.classList.remove('active');
            }
        });
    }
}

// Enhanced profile dropdown functionality
function initProfileDropdown() {
    const profileBtn = document.getElementById('profile-btn');
    const profileMenu = document.getElementById('profile-menu');
    const logoutBtn = document.getElementById('logout-btn');
    const profileLink = document.querySelector('a[href="profile.html"]');
    
    if (profileBtn && profileMenu) {
        // Profile button click handler
        profileBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            const isVisible = profileMenu.style.display === 'block';
            profileMenu.style.display = isVisible ? 'none' : 'block';
        });
        
        // Close dropdown when clicking outside
        document.addEventListener('click', (e) => {
            if (!profileBtn.contains(e.target) && !profileMenu.contains(e.target)) {
                profileMenu.style.display = 'none';
            }
        });
        
        // Prevent dropdown from closing when clicking inside the menu
        profileMenu.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }
    
    // Profile link handler
    if (profileLink) {
        profileLink.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            window.location.href = 'profile.html';
        });
    }
    
    // Logout button handler
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            // Clear all localStorage data
            localStorage.clear();
            
            // Close the dropdown
            if (profileMenu) {
                profileMenu.style.display = 'none';
            }
            
            // Redirect to index page
            window.location.href = '/';
        });
    }
}

// Initialize all enhanced animations and interactions
function initEnhancedUI() {
    if (window.__WebShieldEnhancedUIInitialized) {
        return;
    }
    window.__WebShieldEnhancedUIInitialized = true;

    // Check if user prefers reduced motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    
    if (!prefersReducedMotion) {
        initScrollAnimations();
        initParallaxEffect();
        initScrollProgress();
    }
    
    initSmoothScroll();
    initButtonAnimations();
    initMobileMenu();
    initProfileDropdown();
    
    console.log('✅ Enhanced UI initialized');
}

// Auto-initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initEnhancedUI);

// Export functions for manual initialization if needed
window.WebShieldUI = {
    initScrollAnimations,
    initSmoothScroll,
    initButtonAnimations,
    initParallaxEffect,
    initScrollProgress,
    initMobileMenu,
    initProfileDropdown,
    initEnhancedUI
};
