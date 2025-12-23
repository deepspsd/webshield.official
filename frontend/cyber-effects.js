/**
 * WebShield Cyber Effects System v2.0
 * Professional-grade cyber security animations and effects
 * Creates an immersive, world-class security experience
 */

class CyberEffects {
    constructor() {
        this.canvas = null;
        this.ctx = null;
        this.particles = [];
        this.matrixChars = [];
        this.scanLines = [];
        this.threatNodes = [];
        this.isRunning = false;
        this.animationFrame = null;
        this.mouseX = 0;
        this.mouseY = 0;

        // Configuration
        this.config = {
            particleCount: 80,
            matrixColumns: 50,
            connectionDistance: 150,
            particleSpeed: 0.5,
            glowIntensity: 0.8,
            primaryColor: { r: 59, g: 130, b: 246 },    // Blue
            accentColor: { r: 16, g: 185, b: 129 },     // Green
            warningColor: { r: 245, g: 158, b: 11 },    // Yellow
            dangerColor: { r: 239, g: 68, b: 68 }       // Red
        };

        this.init();
    }

    init() {
        // Don't initialize if reduced motion is preferred
        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            return;
        }

        this.createCanvas();
        this.createParticles();
        this.createMatrixRain();
        this.bindEvents();
        this.start();

        console.log('🛡️ WebShield Cyber Effects initialized');
    }

    createCanvas() {
        // Check if canvas already exists
        if (document.getElementById('cyber-canvas')) {
            this.canvas = document.getElementById('cyber-canvas');
        } else {
            this.canvas = document.createElement('canvas');
            this.canvas.id = 'cyber-canvas';
            this.canvas.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: 0;
                opacity: 0.7;
            `;
            document.body.insertBefore(this.canvas, document.body.firstChild);
        }

        this.ctx = this.canvas.getContext('2d');
        this.resize();
    }

    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }

    createParticles() {
        this.particles = [];
        for (let i = 0; i < this.config.particleCount; i++) {
            this.particles.push({
                x: Math.random() * this.canvas.width,
                y: Math.random() * this.canvas.height,
                vx: (Math.random() - 0.5) * this.config.particleSpeed,
                vy: (Math.random() - 0.5) * this.config.particleSpeed,
                size: Math.random() * 2 + 1,
                opacity: Math.random() * 0.5 + 0.2,
                color: Math.random() > 0.5 ? this.config.primaryColor : this.config.accentColor,
                pulse: Math.random() * Math.PI * 2
            });
        }
    }

    createMatrixRain() {
        this.matrixChars = [];
        const columns = Math.floor(this.canvas.width / 20);

        for (let i = 0; i < columns; i++) {
            this.matrixChars.push({
                x: i * 20,
                y: Math.random() * this.canvas.height,
                speed: Math.random() * 2 + 1,
                chars: this.generateMatrixChars(),
                opacity: Math.random() * 0.15 + 0.05
            });
        }
    }

    generateMatrixChars() {
        const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
        let result = '';
        for (let i = 0; i < 20; i++) {
            result += chars[Math.floor(Math.random() * chars.length)];
        }
        return result;
    }

    bindEvents() {
        window.addEventListener('resize', () => {
            this.resize();
            this.createParticles();
            this.createMatrixRain();
        });

        document.addEventListener('mousemove', (e) => {
            this.mouseX = e.clientX;
            this.mouseY = e.clientY;
        });
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this.animate();
    }

    stop() {
        this.isRunning = false;
        if (this.animationFrame) {
            cancelAnimationFrame(this.animationFrame);
        }
    }

    animate() {
        if (!this.isRunning) return;

        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

        this.drawMatrixRain();
        this.drawParticles();
        this.drawConnections();
        this.drawHexGrid();
        this.drawScanEffect();

        this.animationFrame = requestAnimationFrame(() => this.animate());
    }

    drawParticles() {
        this.particles.forEach(particle => {
            // Update position
            particle.x += particle.vx;
            particle.y += particle.vy;
            particle.pulse += 0.02;

            // Mouse interaction
            const dx = this.mouseX - particle.x;
            const dy = this.mouseY - particle.y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < 100) {
                particle.vx -= dx * 0.0001;
                particle.vy -= dy * 0.0001;
            }

            // Wrap around screen
            if (particle.x < 0) particle.x = this.canvas.width;
            if (particle.x > this.canvas.width) particle.x = 0;
            if (particle.y < 0) particle.y = this.canvas.height;
            if (particle.y > this.canvas.height) particle.y = 0;

            // Draw particle with glow
            const pulseOpacity = particle.opacity + Math.sin(particle.pulse) * 0.2;
            const { r, g, b } = particle.color;

            // Outer glow
            const gradient = this.ctx.createRadialGradient(
                particle.x, particle.y, 0,
                particle.x, particle.y, particle.size * 4
            );
            gradient.addColorStop(0, `rgba(${r}, ${g}, ${b}, ${pulseOpacity})`);
            gradient.addColorStop(1, `rgba(${r}, ${g}, ${b}, 0)`);

            this.ctx.beginPath();
            this.ctx.arc(particle.x, particle.y, particle.size * 4, 0, Math.PI * 2);
            this.ctx.fillStyle = gradient;
            this.ctx.fill();

            // Core
            this.ctx.beginPath();
            this.ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
            this.ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${pulseOpacity + 0.3})`;
            this.ctx.fill();
        });
    }

    drawConnections() {
        for (let i = 0; i < this.particles.length; i++) {
            for (let j = i + 1; j < this.particles.length; j++) {
                const dx = this.particles[i].x - this.particles[j].x;
                const dy = this.particles[i].y - this.particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < this.config.connectionDistance) {
                    const opacity = (1 - dist / this.config.connectionDistance) * 0.15;
                    const { r, g, b } = this.config.primaryColor;

                    this.ctx.beginPath();
                    this.ctx.moveTo(this.particles[i].x, this.particles[i].y);
                    this.ctx.lineTo(this.particles[j].x, this.particles[j].y);
                    this.ctx.strokeStyle = `rgba(${r}, ${g}, ${b}, ${opacity})`;
                    this.ctx.lineWidth = 0.5;
                    this.ctx.stroke();
                }
            }
        }
    }

    drawMatrixRain() {
        this.ctx.font = '14px monospace';

        this.matrixChars.forEach(column => {
            column.y += column.speed;

            if (column.y > this.canvas.height) {
                column.y = -400;
                column.chars = this.generateMatrixChars();
            }

            for (let i = 0; i < column.chars.length; i++) {
                const y = column.y + i * 20;
                const opacity = column.opacity * (1 - i / column.chars.length);

                // First character is brighter (leading edge)
                if (i === 0) {
                    this.ctx.fillStyle = `rgba(16, 185, 129, ${opacity * 3})`;
                } else {
                    this.ctx.fillStyle = `rgba(16, 185, 129, ${opacity})`;
                }

                this.ctx.fillText(column.chars[i], column.x, y);
            }
        });
    }

    drawHexGrid() {
        const hexSize = 60;
        const time = Date.now() * 0.001;

        this.ctx.strokeStyle = 'rgba(59, 130, 246, 0.03)';
        this.ctx.lineWidth = 1;

        for (let row = 0; row < this.canvas.height / hexSize + 1; row++) {
            for (let col = 0; col < this.canvas.width / hexSize + 1; col++) {
                const x = col * hexSize * 1.5 + (row % 2) * hexSize * 0.75;
                const y = row * hexSize * 0.866;

                const pulse = Math.sin(time + col * 0.3 + row * 0.3) * 0.02 + 0.03;
                this.ctx.strokeStyle = `rgba(59, 130, 246, ${pulse})`;

                this.drawHexagon(x, y, hexSize / 2);
            }
        }
    }

    drawHexagon(x, y, size) {
        this.ctx.beginPath();
        for (let i = 0; i < 6; i++) {
            const angle = (i * Math.PI) / 3;
            const xPos = x + size * Math.cos(angle);
            const yPos = y + size * Math.sin(angle);

            if (i === 0) {
                this.ctx.moveTo(xPos, yPos);
            } else {
                this.ctx.lineTo(xPos, yPos);
            }
        }
        this.ctx.closePath();
        this.ctx.stroke();
    }

    drawScanEffect() {
        const time = Date.now() * 0.001;
        const scanY = ((time * 50) % (this.canvas.height + 200)) - 100;

        // Horizontal scan line
        const gradient = this.ctx.createLinearGradient(0, scanY - 50, 0, scanY + 50);
        gradient.addColorStop(0, 'rgba(59, 130, 246, 0)');
        gradient.addColorStop(0.5, 'rgba(59, 130, 246, 0.1)');
        gradient.addColorStop(1, 'rgba(59, 130, 246, 0)');

        this.ctx.fillStyle = gradient;
        this.ctx.fillRect(0, scanY - 50, this.canvas.width, 100);

        // Bright scan line
        this.ctx.beginPath();
        this.ctx.moveTo(0, scanY);
        this.ctx.lineTo(this.canvas.width, scanY);
        this.ctx.strokeStyle = 'rgba(59, 130, 246, 0.3)';
        this.ctx.lineWidth = 2;
        this.ctx.stroke();
    }

    // Public method to trigger threat detection animation
    triggerThreatAnimation(element, type = 'warning') {
        if (!element) return;

        const colors = {
            safe: 'rgba(16, 185, 129, 0.5)',
            warning: 'rgba(245, 158, 11, 0.5)',
            danger: 'rgba(239, 68, 68, 0.5)'
        };

        element.style.animation = 'threatPulse 0.5s ease-out';
        element.style.boxShadow = `0 0 30px ${colors[type]}`;

        setTimeout(() => {
            element.style.animation = '';
            element.style.boxShadow = '';
        }, 500);
    }

    // Create scanning animation for an element
    createScanAnimation(element) {
        if (!element) return;

        const scanLine = document.createElement('div');
        scanLine.className = 'cyber-scan-line';
        scanLine.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.8), transparent);
            animation: scanDown 1.5s ease-in-out infinite;
            pointer-events: none;
            z-index: 100;
        `;

        element.style.position = 'relative';
        element.appendChild(scanLine);

        return () => scanLine.remove();
    }
}

/**
 * Advanced Loading Animation System
 */
class CyberLoader {
    constructor() {
        this.loaderElement = null;
        this.init();
    }

    init() {
        this.createStyles();
    }

    createStyles() {
        if (document.getElementById('cyber-loader-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'cyber-loader-styles';
        styles.textContent = `
            .cyber-loader-overlay {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.9);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                backdrop-filter: blur(10px);
            }
            
            .cyber-loader-container {
                text-align: center;
            }
            
            .cyber-loader {
                width: 120px;
                height: 120px;
                position: relative;
                margin: 0 auto 2rem;
            }
            
            .cyber-loader-ring {
                position: absolute;
                width: 100%;
                height: 100%;
                border-radius: 50%;
                border: 3px solid transparent;
            }
            
            .cyber-loader-ring:nth-child(1) {
                border-top-color: #3b82f6;
                animation: cyberSpin 1.5s linear infinite;
            }
            
            .cyber-loader-ring:nth-child(2) {
                width: 80%;
                height: 80%;
                top: 10%;
                left: 10%;
                border-right-color: #10b981;
                animation: cyberSpin 1.2s linear infinite reverse;
            }
            
            .cyber-loader-ring:nth-child(3) {
                width: 60%;
                height: 60%;
                top: 20%;
                left: 20%;
                border-bottom-color: #f59e0b;
                animation: cyberSpin 0.9s linear infinite;
            }
            
            .cyber-loader-core {
                position: absolute;
                width: 30%;
                height: 30%;
                top: 35%;
                left: 35%;
                background: linear-gradient(135deg, #3b82f6, #10b981);
                border-radius: 50%;
                animation: cyberPulse 1s ease-in-out infinite;
                box-shadow: 0 0 30px rgba(59, 130, 246, 0.5);
            }
            
            .cyber-loader-text {
                color: white;
                font-size: 1.25rem;
                font-weight: 600;
                margin-bottom: 0.5rem;
                text-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
            }
            
            .cyber-loader-subtext {
                color: rgba(255, 255, 255, 0.6);
                font-size: 0.875rem;
            }
            
            .cyber-loader-progress {
                width: 200px;
                height: 4px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 2px;
                margin: 1.5rem auto 0;
                overflow: hidden;
            }
            
            .cyber-loader-progress-bar {
                height: 100%;
                width: 0%;
                background: linear-gradient(90deg, #3b82f6, #10b981);
                border-radius: 2px;
                transition: width 0.3s ease;
                box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);
            }
            
            @keyframes cyberSpin {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
            
            @keyframes cyberPulse {
                0%, 100% { transform: scale(1); opacity: 1; }
                50% { transform: scale(1.2); opacity: 0.8; }
            }
            
            /* Shield Scanner Animation */
            .shield-scanner {
                position: relative;
                width: 150px;
                height: 150px;
                margin: 0 auto 2rem;
            }
            
            .shield-outer {
                position: absolute;
                width: 100%;
                height: 100%;
                border: 3px solid rgba(59, 130, 246, 0.3);
                border-radius: 50%;
                animation: shieldPulse 2s ease-in-out infinite;
            }
            
            .shield-inner {
                position: absolute;
                width: 70%;
                height: 70%;
                top: 15%;
                left: 15%;
                border: 2px solid rgba(16, 185, 129, 0.5);
                border-radius: 50%;
                animation: shieldPulse 2s ease-in-out infinite 0.5s;
            }
            
            .shield-core {
                position: absolute;
                width: 40%;
                height: 40%;
                top: 30%;
                left: 30%;
                background: linear-gradient(135deg, #3b82f6, #10b981);
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                box-shadow: 0 0 40px rgba(59, 130, 246, 0.5);
                animation: shieldGlow 1.5s ease-in-out infinite;
            }
            
            .shield-core svg {
                width: 60%;
                height: 60%;
                color: white;
            }
            
            .shield-scan-line {
                position: absolute;
                width: 100%;
                height: 2px;
                background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.8), transparent);
                top: 50%;
                left: 0;
                animation: shieldScan 2s linear infinite;
                transform-origin: center;
            }
            
            @keyframes shieldPulse {
                0%, 100% { transform: scale(1); opacity: 1; }
                50% { transform: scale(1.1); opacity: 0.6; }
            }
            
            @keyframes shieldGlow {
                0%, 100% { box-shadow: 0 0 40px rgba(59, 130, 246, 0.5); }
                50% { box-shadow: 0 0 60px rgba(16, 185, 129, 0.6); }
            }
            
            @keyframes shieldScan {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
            }
        `;
        document.head.appendChild(styles);
    }

    show(text = 'Scanning...', subtext = 'Analyzing URL for threats', maxTimeout = 15000) {
        if (this.loaderElement) this.hide();

        // Clear any existing timeout
        if (this.autoHideTimeout) {
            clearTimeout(this.autoHideTimeout);
        }

        this.loaderElement = document.createElement('div');
        this.loaderElement.className = 'cyber-loader-overlay';
        this.loaderElement.innerHTML = `
            <div class="cyber-loader-container">
                <div class="shield-scanner">
                    <div class="shield-outer"></div>
                    <div class="shield-inner"></div>
                    <div class="shield-core">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        </svg>
                    </div>
                    <div class="shield-scan-line"></div>
                </div>
                <div class="cyber-loader-text">${text}</div>
                <div class="cyber-loader-subtext">${subtext}</div>
                <div class="cyber-loader-progress">
                    <div class="cyber-loader-progress-bar"></div>
                </div>
            </div>
        `;

        document.body.appendChild(this.loaderElement);

        // Animate progress
        setTimeout(() => this.updateProgress(30), 200);
        setTimeout(() => this.updateProgress(60), 500);
        setTimeout(() => this.updateProgress(80), 800);

        // Auto-hide after maxTimeout to prevent infinite loading
        this.autoHideTimeout = setTimeout(() => {
            console.log('⏰ CyberLoader auto-timeout reached - hiding loader');
            this.hide();
        }, maxTimeout);
    }

    updateProgress(percent) {
        if (!this.loaderElement) return;
        const progressBar = this.loaderElement.querySelector('.cyber-loader-progress-bar');
        if (progressBar) {
            progressBar.style.width = percent + '%';
        }
    }

    updateText(text, subtext) {
        if (!this.loaderElement) return;
        const textEl = this.loaderElement.querySelector('.cyber-loader-text');
        const subtextEl = this.loaderElement.querySelector('.cyber-loader-subtext');
        if (textEl) textEl.textContent = text;
        if (subtextEl) subtextEl.textContent = subtext;
    }

    hide() {
        // Clear the auto-hide timeout
        if (this.autoHideTimeout) {
            clearTimeout(this.autoHideTimeout);
            this.autoHideTimeout = null;
        }

        if (this.loaderElement) {
            this.loaderElement.style.opacity = '0';
            this.loaderElement.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                if (this.loaderElement) {
                    this.loaderElement.remove();
                    this.loaderElement = null;
                }
            }, 300);
        }
    }
}

/**
 * Scroll Reveal Animation System
 */
class ScrollReveal {
    constructor() {
        this.elements = [];
        this.observer = null;
        this.init();
    }

    init() {
        this.createStyles();
        this.setupObserver();
        this.observeElements();
    }

    createStyles() {
        if (document.getElementById('scroll-reveal-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'scroll-reveal-styles';
        styles.textContent = `
            .reveal {
                opacity: 0;
                transform: translateY(50px);
                transition: all 0.8s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .reveal.revealed {
                opacity: 1;
                transform: translateY(0);
            }
            
            .reveal-left {
                opacity: 0;
                transform: translateX(-50px);
                transition: all 0.8s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .reveal-left.revealed {
                opacity: 1;
                transform: translateX(0);
            }
            
            .reveal-right {
                opacity: 0;
                transform: translateX(50px);
                transition: all 0.8s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .reveal-right.revealed {
                opacity: 1;
                transform: translateX(0);
            }
            
            .reveal-scale {
                opacity: 0;
                transform: scale(0.8);
                transition: all 0.8s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .reveal-scale.revealed {
                opacity: 1;
                transform: scale(1);
            }
            
            .reveal-rotate {
                opacity: 0;
                transform: rotate(-10deg) scale(0.9);
                transition: all 0.8s cubic-bezier(0.4, 0, 0.2, 1);
            }
            
            .reveal-rotate.revealed {
                opacity: 1;
                transform: rotate(0) scale(1);
            }
            
            /* Staggered delays */
            .reveal-delay-1 { transition-delay: 0.1s; }
            .reveal-delay-2 { transition-delay: 0.2s; }
            .reveal-delay-3 { transition-delay: 0.3s; }
            .reveal-delay-4 { transition-delay: 0.4s; }
            .reveal-delay-5 { transition-delay: 0.5s; }
            .reveal-delay-6 { transition-delay: 0.6s; }
        `;
        document.head.appendChild(styles);
    }

    setupObserver() {
        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            // Skip animations for reduced motion preference
            document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-scale, .reveal-rotate').forEach(el => {
                el.classList.add('revealed');
            });
            return;
        }

        this.observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('revealed');
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        });
    }

    observeElements() {
        if (!this.observer) return;

        document.querySelectorAll('.reveal, .reveal-left, .reveal-right, .reveal-scale, .reveal-rotate').forEach(el => {
            this.observer.observe(el);
        });
    }

    // Call this when new elements are added to the DOM
    refresh() {
        this.observeElements();
    }
}

/**
 * Magnetic Hover Effect
 */
class MagneticHover {
    constructor() {
        this.init();
    }

    init() {
        document.querySelectorAll('.magnetic').forEach(element => {
            this.setupElement(element);
        });
    }

    setupElement(element) {
        element.addEventListener('mousemove', (e) => {
            const rect = element.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;

            element.style.transform = `translate(${x * 0.2}px, ${y * 0.2}px)`;
        });

        element.addEventListener('mouseleave', () => {
            element.style.transform = '';
            element.style.transition = 'transform 0.3s ease';
        });

        element.addEventListener('mouseenter', () => {
            element.style.transition = 'transform 0.1s ease';
        });
    }
}

/**
 * Typing Animation Effect
 */
class TypeWriter {
    constructor(element, text, speed = 50) {
        this.element = element;
        this.text = text;
        this.speed = speed;
        this.index = 0;
    }

    start() {
        return new Promise((resolve) => {
            this.element.textContent = '';
            this.type(resolve);
        });
    }

    type(resolve) {
        if (this.index < this.text.length) {
            this.element.textContent += this.text.charAt(this.index);
            this.index++;
            setTimeout(() => this.type(resolve), this.speed);
        } else {
            resolve();
        }
    }
}

/**
 * Ripple Effect for Buttons
 */
class RippleEffect {
    constructor() {
        this.init();
    }

    init() {
        this.createStyles();

        document.querySelectorAll('.btn, .ripple').forEach(button => {
            button.addEventListener('click', (e) => this.createRipple(e, button));
        });
    }

    createStyles() {
        if (document.getElementById('ripple-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'ripple-styles';
        styles.textContent = `
            .ripple-container {
                position: relative;
                overflow: hidden;
            }
            
            .ripple-effect {
                position: absolute;
                border-radius: 50%;
                background: rgba(255, 255, 255, 0.4);
                transform: scale(0);
                animation: ripple 0.6s ease-out;
                pointer-events: none;
            }
            
            @keyframes ripple {
                to {
                    transform: scale(4);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(styles);
    }

    createRipple(e, button) {
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = e.clientX - rect.left - size / 2;
        const y = e.clientY - rect.top - size / 2;

        const ripple = document.createElement('span');
        ripple.className = 'ripple-effect';
        ripple.style.cssText = `
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
        `;

        button.style.position = 'relative';
        button.style.overflow = 'hidden';
        button.appendChild(ripple);

        setTimeout(() => ripple.remove(), 600);
    }
}

/**
 * Threat Level Indicator Animation
 */
class ThreatIndicator {
    constructor() {
        this.createStyles();
    }

    createStyles() {
        if (document.getElementById('threat-indicator-styles')) return;

        const styles = document.createElement('style');
        styles.id = 'threat-indicator-styles';
        styles.textContent = `
            .threat-indicator {
                display: flex;
                align-items: center;
                gap: 0.5rem;
                padding: 0.5rem 1rem;
                border-radius: 2rem;
                font-weight: 600;
                font-size: 0.875rem;
                transition: all 0.3s ease;
            }
            
            .threat-safe {
                background: rgba(16, 185, 129, 0.1);
                border: 1px solid rgba(16, 185, 129, 0.3);
                color: #10b981;
                animation: safePulse 2s ease-in-out infinite;
            }
            
            .threat-warning {
                background: rgba(245, 158, 11, 0.1);
                border: 1px solid rgba(245, 158, 11, 0.3);
                color: #f59e0b;
                animation: warningPulse 1.5s ease-in-out infinite;
            }
            
            .threat-danger {
                background: rgba(239, 68, 68, 0.1);
                border: 1px solid rgba(239, 68, 68, 0.3);
                color: #ef4444;
                animation: dangerPulse 1s ease-in-out infinite;
            }
            
            .threat-indicator-icon {
                width: 1.25rem;
                height: 1.25rem;
            }
            
            .threat-indicator-dot {
                width: 0.5rem;
                height: 0.5rem;
                border-radius: 50%;
                animation: dotPulse 1s ease-in-out infinite;
            }
            
            .threat-safe .threat-indicator-dot { background: #10b981; }
            .threat-warning .threat-indicator-dot { background: #f59e0b; }
            .threat-danger .threat-indicator-dot { background: #ef4444; }
            
            @keyframes safePulse {
                0%, 100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.2); }
                50% { box-shadow: 0 0 20px 5px rgba(16, 185, 129, 0.3); }
            }
            
            @keyframes warningPulse {
                0%, 100% { box-shadow: 0 0 0 0 rgba(245, 158, 11, 0.2); }
                50% { box-shadow: 0 0 20px 5px rgba(245, 158, 11, 0.3); }
            }
            
            @keyframes dangerPulse {
                0%, 100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.2); transform: scale(1); }
                50% { box-shadow: 0 0 30px 10px rgba(239, 68, 68, 0.4); transform: scale(1.02); }
            }
            
            @keyframes dotPulse {
                0%, 100% { opacity: 1; transform: scale(1); }
                50% { opacity: 0.5; transform: scale(1.2); }
            }
        `;
        document.head.appendChild(styles);
    }

    create(level, text) {
        const indicator = document.createElement('div');
        indicator.className = `threat-indicator threat-${level}`;
        indicator.innerHTML = `
            <span class="threat-indicator-dot"></span>
            <span>${text}</span>
        `;
        return indicator;
    }
}

/**
 * Number Counter Animation
 */
class CounterAnimation {
    constructor(element, target, duration = 2000) {
        this.element = element;
        this.target = target;
        this.duration = duration;
        this.startTime = null;
        this.startValue = 0;
    }

    start() {
        this.startTime = performance.now();
        this.animate();
    }

    animate() {
        const currentTime = performance.now();
        const elapsed = currentTime - this.startTime;
        const progress = Math.min(elapsed / this.duration, 1);

        // Easing function (ease-out-quart)
        const eased = 1 - Math.pow(1 - progress, 4);
        const current = Math.floor(this.startValue + (this.target - this.startValue) * eased);

        this.element.textContent = current.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(() => this.animate());
        }
    }
}

// Global initialization
let cyberEffects = null;
let cyberLoader = null;
let scrollReveal = null;
let magneticHover = null;
let rippleEffect = null;
let threatIndicator = null;

function initCyberEffects() {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initialize);
    } else {
        initialize();
    }
}

function initialize() {
    // Initialize all effects
    cyberEffects = new CyberEffects();
    cyberLoader = new CyberLoader();
    scrollReveal = new ScrollReveal();
    magneticHover = new MagneticHover();
    rippleEffect = new RippleEffect();
    threatIndicator = new ThreatIndicator();

    console.log('🚀 All Cyber Effects Systems initialized');
}

// Auto-initialize
initCyberEffects();

// Export for global access
window.CyberEffects = CyberEffects;
window.CyberLoader = CyberLoader;
window.ScrollReveal = ScrollReveal;
window.MagneticHover = MagneticHover;
window.TypeWriter = TypeWriter;
window.RippleEffect = RippleEffect;
window.ThreatIndicator = ThreatIndicator;
window.CounterAnimation = CounterAnimation;

// Convenience functions
window.showCyberLoader = (text, subtext) => cyberLoader?.show(text, subtext);
window.hideCyberLoader = () => cyberLoader?.hide();
window.updateCyberLoaderProgress = (percent) => cyberLoader?.updateProgress(percent);
window.updateCyberLoaderText = (text, subtext) => cyberLoader?.updateText(text, subtext);
window.createThreatIndicator = (level, text) => threatIndicator?.create(level, text);
