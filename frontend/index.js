// ==========================================================================
// AIPIF LANDING PAGE JAVASCRIPT - ENHANCED WITH MOBILE MENU
// ==========================================================================

class AIPIFLandingPage {
    constructor() {
        this.mobileMenuOpen = false;
        this.userMenuOpen = false;
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.scanCount = 0;
        this.totalThreats = 0;
        this.totalScanTime = 0;
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            console.log('🚀 AIPIF Landing Page Initializing...');
            this.initializePage();
        });
    }

    initializePage() {
        try {
            this.initMobileMenu();
            this.initTheme();
            this.initUserDropdown();
            this.checkAuthStatus();
            this.initDemoScanner();
            this.initSmoothScrolling();
            this.initDashboardRedirect();
            this.initIntersectionObserver();
            this.initErrorHandling();
            this.initConfirmationModal();

            // Check auth status periodically
            setInterval(() => this.checkAuthStatus(), 5000);

            console.log('🎉 AIPIF landing page fully initialized!');
        } catch (error) {
            console.error('💥 Failed to initialize landing page:', error);
            this.showNotification('Page initialization failed - please refresh', 'error');
        }
    }

    // ==========================================================================
    // 1. ENHANCED MOBILE MENU FUNCTIONALITY (Like Dashboard)
    // ==========================================================================
    initMobileMenu() {
        console.log('📱 Initializing mobile menu for landing page...');

        try {
            // Create mobile menu toggle button if it doesn't exist
            if (!document.querySelector('.mobile-menu-toggle')) {
                this.menuToggle = document.createElement('button');
                this.menuToggle.className = 'mobile-menu-toggle';
                this.menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
                this.menuToggle.setAttribute('aria-label', 'Toggle menu');

                // Insert at the beginning of the navbar for proper alignment
                const navbar = document.querySelector('.navbar');
                if (navbar) {
                    navbar.insertBefore(this.menuToggle, navbar.firstChild);
                } else {
                    document.body.appendChild(this.menuToggle);
                }
                console.log('✅ Mobile menu toggle created for landing page');
            } else {
                this.menuToggle = document.querySelector('.mobile-menu-toggle');
                console.log('✅ Mobile menu toggle found in landing page');
            }

            // Get or create mobile overlay
            this.overlay = document.getElementById('mobileOverlay');
            if (!this.overlay) {
                this.overlay = document.createElement('div');
                this.overlay.className = 'mobile-overlay';
                this.overlay.id = 'mobileOverlay';
                document.body.appendChild(this.overlay);
                console.log('✅ Mobile overlay created for landing page');
            }

            // Get nav links container
            this.navLinks = document.getElementById('navLinks');

            this.bindMobileMenuEvents();
            console.log('✅ Mobile menu initialized successfully for landing page');

        } catch (error) {
            console.warn('⚠️ Mobile menu initialization failed in landing page:', error);
        }
    }

    bindMobileMenuEvents() {
        if (!this.menuToggle || !this.overlay || !this.navLinks) {
            console.warn('⚠️ Mobile menu elements not found in landing page');
            return;
        }

        console.log('🔧 Binding mobile menu events for landing page...');

        // Toggle menu when button is clicked
        this.menuToggle.addEventListener('click', () => {
            console.log('📱 Mobile menu toggle clicked in landing page');
            this.toggleMobileMenu();
        });

        // Close menu when overlay is clicked
        this.overlay.addEventListener('click', () => {
            console.log('📱 Mobile overlay clicked in landing page');
            this.closeMobileMenu();
        });

        // Close menu when nav items are clicked
        document.querySelectorAll('.nav-link').forEach(item => {
            item.addEventListener('click', () => {
                console.log('📱 Nav item clicked, closing mobile menu');
                this.closeMobileMenu();
            });
        });

        // Close menu on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.mobileMenuOpen) {
                console.log('📱 Escape key pressed, closing mobile menu');
                this.closeMobileMenu();
            }
        });

        // Handle window resize
        window.addEventListener('resize', () => {
            this.handleResize();
        });

        console.log('✅ Mobile menu events bound successfully for landing page');
    }

    toggleMobileMenu() {
        if (!this.navLinks) {
            console.warn('⚠️ Nav links not found for mobile menu in landing page');
            return;
        }

        if (this.mobileMenuOpen) {
            this.closeMobileMenu();
        } else {
            this.openMobileMenu();
        }
    }

    openMobileMenu() {
        console.log('📱 Opening mobile menu in landing page');
        this.navLinks.classList.add('mobile-open');
        this.overlay.classList.add('active');
        this.menuToggle.innerHTML = '<i class="fas fa-times"></i>';
        this.menuToggle.style.zIndex = '1002';
        document.body.style.overflow = 'hidden';
        this.mobileMenuOpen = true;

        setTimeout(() => {
            this.overlay.style.opacity = '1';
        }, 10);
    }

    closeMobileMenu() {
        console.log('📱 Closing mobile menu in landing page');
        this.navLinks.classList.remove('mobile-open');
        this.overlay.style.opacity = '0';
        this.menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
        this.menuToggle.style.zIndex = '1001';
        document.body.style.overflow = '';
        this.mobileMenuOpen = false;

        setTimeout(() => {
            if (!this.mobileMenuOpen) {
                this.overlay.classList.remove('active');
            }
        }, 300);
    }

    handleResize() {
        if (window.innerWidth > 768 && this.mobileMenuOpen) {
            console.log('📱 Window resized to desktop, closing mobile menu');
            this.closeMobileMenu();
        }
    }

    // ==========================================================================
    // 2. IMPROVED THEME MANAGEMENT
    // ==========================================================================
    initTheme() {
        const themeToggle = document.getElementById('themeToggle');
        if (!themeToggle) return;

        // Apply initial theme
        this.applyTheme(this.currentTheme);

        // Enhanced theme toggle with smooth transition
        themeToggle.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.toggleTheme();
        });

        console.log('✅ Enhanced theme management initialized');
    }

    applyTheme(theme) {
        const previousTheme = this.currentTheme;
        this.currentTheme = theme;

        // Apply theme with smooth transition
        requestAnimationFrame(() => {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
            this.updateThemeUI(theme);

            // Dispatch event for other components
            window.dispatchEvent(new CustomEvent('themeChanged', {
                detail: { theme: theme, previousTheme: previousTheme }
            }));
        });
    }

    toggleTheme() {
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        console.log('🔄 Toggling theme from', this.currentTheme, 'to', newTheme);
        this.applyTheme(newTheme);
    }

    updateThemeUI(theme) {
        const themeToggle = document.getElementById('themeToggle');
        if (!themeToggle) return;

        const icon = themeToggle.querySelector('.theme-icon i');
        const text = themeToggle.querySelector('.theme-text');

        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
        if (text) {
            text.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
        }
    }

    // ==========================================================================
    // 3. ENHANCED USER DROPDOWN
    // ==========================================================================
    initUserDropdown() {
        const userToggle = document.getElementById('userToggle');
        const userMenu = document.getElementById('userMenu');
        const logoutButton = document.getElementById('logoutButton');

        if (!userToggle || !userMenu) return;

        // Enhanced toggle with animation
        userToggle.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleUserMenu();
        });

        // Improved outside click detection
        document.addEventListener('click', (e) => {
            if (this.userMenuOpen && !userToggle.contains(e.target) && !userMenu.contains(e.target)) {
                this.closeUserMenu();
            }
        });

        // Enhanced keyboard support
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.userMenuOpen) {
                this.closeUserMenu();
            }
        });

        if (logoutButton) {
            logoutButton.addEventListener('click', () => this.handleLogout());
        }

        console.log('✅ Enhanced user dropdown initialized');
    }

    toggleUserMenu() {
        if (this.userMenuOpen) {
            this.closeUserMenu();
        } else {
            this.openUserMenu();
        }
    }

    openUserMenu() {
        const userMenu = document.getElementById('userMenu');
        const userToggle = document.getElementById('userToggle');

        if (userMenu && userToggle) {
            userMenu.classList.add('active');
            userToggle.classList.add('active');
            this.userMenuOpen = true;
        }
    }

    closeUserMenu() {
        const userMenu = document.getElementById('userMenu');
        const userToggle = document.getElementById('userToggle');

        if (userMenu && userToggle) {
            userMenu.classList.remove('active');
            userToggle.classList.remove('active');
            this.userMenuOpen = false;
        }
    }

    // ==========================================================================
    // 4. AUTHENTICATION MANAGEMENT
    // ==========================================================================
    checkAuthStatus() {
        const authButtons = document.getElementById('userAuthButtons');
        const userProfile = document.getElementById('userProfile');

        if (!authButtons || !userProfile) return;

        const token = localStorage.getItem('authToken');
        const user = JSON.parse(localStorage.getItem('userData') || 'null');

        if (token && user) {
            // Smooth transition to logged-in state
            authButtons.style.opacity = '0';
            userProfile.style.opacity = '0';

            setTimeout(() => {
                authButtons.style.display = 'none';
                userProfile.style.display = 'block';
                requestAnimationFrame(() => {
                    authButtons.style.opacity = '';
                    userProfile.style.opacity = '1';
                });
            }, 150);

            this.updateUserInfo(user);
        } else {
            // Smooth transition to logged-out state
            userProfile.style.opacity = '0';
            authButtons.style.opacity = '0';

            setTimeout(() => {
                userProfile.style.display = 'none';
                authButtons.style.display = 'flex';
                requestAnimationFrame(() => {
                    userProfile.style.opacity = '';
                    authButtons.style.opacity = '1';
                });
            }, 150);
        }
    }

    updateUserInfo(user) {
        const userName = document.getElementById('userName');
        const userEmail = document.getElementById('userEmail');
        const userAvatar = document.querySelector('.user-avatar');

        if (userName) {
            userName.textContent = user.username || 'AIPIF User';
        }
        if (userEmail) {
            userEmail.textContent = user.email || 'user@aipif.com';
        }
        if (userAvatar && user.username) {
            userAvatar.textContent = user.username.substring(0, 2).toUpperCase();
        }
    }

    handleLogout() {
        console.log('🚪 Logging out user...');

        if (window.confirmationModal) {
            window.confirmationModal.show(
                'Are you sure you want to logout?',
                'Logout',
                'Cancel',
                'warning'
            ).then(confirmed => {
                if (confirmed) {
                    this.performLogout();
                }
            });
        } else {
            if (confirm('Are you sure you want to logout?')) {
                this.performLogout();
            }
        }
    }

    performLogout() {
        // Close user menu if open
        this.closeUserMenu();

        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');

        this.showNotification('Successfully logged out', 'success');

        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
    }

    // ==========================================================================
    // 5. DEMO SCANNER WITH ENHANCED UX (Matches Dashboard Style)
    // ==========================================================================
    initDemoScanner() {
        const demoScanButton = document.getElementById('demoScanButton');
        const clearScannerButton = document.getElementById('clearScannerButton');
        const promptInput = document.getElementById('demoPrompt');

        if (!demoScanButton || !promptInput) return;

        // Enhanced click handler
        demoScanButton.addEventListener('click', () => this.handleDemoScan());

        // Clear scanner functionality
        if (clearScannerButton) {
            clearScannerButton.addEventListener('click', () => this.clearDemoScanner());
        }

        // Improved keyboard handling
        promptInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                this.handleDemoScan();
            }
        });

        // Auto-resize textarea
        promptInput.addEventListener('input', () => {
            this.autoResizeTextarea(promptInput);
        });

        console.log('✅ Enhanced demo scanner initialized');
    }

    autoResizeTextarea(textarea) {
        textarea.style.height = 'auto';
        textarea.style.height = Math.min(textarea.scrollHeight, 200) + 'px';
    }

    async handleDemoScan() {
        const promptInput = document.getElementById('demoPrompt');
        const resultContainer = document.getElementById('demoResult');
        const scanButton = document.getElementById('demoScanButton');

        if (!promptInput || !resultContainer || !scanButton) return;

        const prompt = promptInput.value.trim();
        if (!prompt) {
            this.showResult('Please enter a prompt to scan', 'error');
            promptInput.focus();
            return;
        }

        // Enhanced loading state
        const originalContent = scanButton.innerHTML;
        scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
        scanButton.disabled = true;

        // Add loading animation to result container
        resultContainer.style.opacity = '0.7';

        try {
            const startTime = Date.now();
            const result = await this.simulateScan(prompt);
            const scanTime = Date.now() - startTime;

            this.displayDemoResult(result, scanTime);
            this.showNotification('Security scan completed successfully', 'success');

            // Update scanner stats (like dashboard)
            this.scanCount++;
            if (result.risk_score >= 30) this.totalThreats++;
            this.totalScanTime += scanTime;
            this.updateScannerStats();

        } catch (error) {
            console.error('Scan error:', error);
            this.showResult('Scan failed: ' + error.message, 'error');
            this.showNotification('Scan failed - please try again', 'error');
        } finally {
            // Smooth restore of button state
            setTimeout(() => {
                scanButton.innerHTML = originalContent;
                scanButton.disabled = false;
                resultContainer.style.opacity = '1';
            }, 300);
        }
    }

    clearDemoScanner() {
        const promptInput = document.getElementById('demoPrompt');
        const resultContainer = document.getElementById('demoResult');

        if (promptInput) promptInput.value = '';
        if (resultContainer) {
            resultContainer.innerHTML = `
                <div class="result-placeholder">
                    <i class="fas fa-search"></i>
                    <h4>Ready to Scan</h4>
                    <p>Enter a prompt above to begin security analysis</p>
                    <div class="scanner-tips">
                        <p><strong>Tip:</strong> Try the example prompts to test the scanner</p>
                    </div>
                </div>
            `;
        }
    }

    updateScannerStats() {
        const totalScans = document.getElementById('totalScansCount');
        const threatsDetected = document.getElementById('threatsDetected');
        const avgScanTime = document.getElementById('avgScanTime');

        if (totalScans) totalScans.textContent = this.scanCount;
        if (threatsDetected) threatsDetected.textContent = this.totalThreats;

        const avgTime = this.scanCount > 0 ? Math.round(this.totalScanTime / this.scanCount) : 0;
        if (avgScanTime) avgScanTime.textContent = `${avgTime}ms`;
    }

    simulateScan(prompt) {
        return new Promise((resolve) => {
            // Simulate API call with progressive loading
            const startTime = Date.now();
            const minDelay = 800;
            const maxDelay = 2000;
            const delay = Math.random() * (maxDelay - minDelay) + minDelay;

            setTimeout(() => {
                const riskScore = this.calculateRiskScore(prompt);
                const category = riskScore >= 75 ? 'malicious' : riskScore >= 40 ? 'suspicious' : 'safe';
                const findings = this.generateFindings(prompt, riskScore);

                resolve({
                    risk_score: riskScore,
                    category: category,
                    explanation: {
                        findings: findings,
                        confidence: Math.floor(Math.random() * 10) + 90,
                        processing_time: Date.now() - startTime
                    }
                });
            }, delay);
        });
    }

    calculateRiskScore(prompt) {
        let score = 0;
        const lowerPrompt = prompt.toLowerCase();

        // Enhanced detection patterns
        const patterns = [
            { regex: /ignore\s+previous\s+instructions/i, weight: 50 },
            { regex: /system\s+prompt|disregard\s+previous|new\s+rule/i, weight: 40 },
            { regex: /(<\s*script\s*>|<\/\s*script\s*>)/i, weight: 60 },
            { regex: /\b(ls|cat|rm|exec|eval)\s+[^\s]*/i, weight: 45 },
            { regex: /javascript:|document\.cookie|window\.(location|open)/i, weight: 40 },
            { regex: /;/, weight: 15 },
            { regex: /base64/, weight: 30 },
            { regex: /http:\/\//, weight: 15 }
        ];

        patterns.forEach(pattern => {
            if (pattern.regex.test(prompt)) {
                score += pattern.weight;
            }
        });

        // Add slight randomness for demo purposes
        score += Math.random() * 5;

        return Math.min(Math.floor(score), 100);
    }

    generateFindings(prompt, riskScore) {
        const findings = [];

        if (riskScore >= 75) {
            findings.push('High-Confidence **Malicious Injection** attempt detected.');
            findings.push('The prompt contains keywords targeting **System Prompt Extraction**.');
            findings.push('Active command/scripting indicators found.');
            findings.push('Immediate blocking required.');
        } else if (riskScore >= 40) {
            findings.push('**Suspicious** pattern detected with multiple non-standard commands.');
            if (prompt.includes('script')) findings.push('Contains scripting language fragments (potential XSS/HTML injection).');
            if (prompt.includes('ignore')) findings.push('Attempt to bypass security constraints noted.');
            findings.push('Requires human review for final policy decision.');
        } else {
            findings.push('No critical security threats detected.');
            findings.push('Prompt is categorized as **Safe** for standard processing.');
        }

        return findings;
    }

    displayDemoResult(result, scanTime) {
        const container = document.getElementById('demoResult');
        if (!container) return;

        const riskClass = result.category;
        const riskIcon = result.category === 'malicious' ? 'fa-exclamation-triangle' :
                         result.category === 'suspicious' ? 'fa-info-circle' : 'fa-check-circle';

        // Smooth transition for result display
        container.style.opacity = '0';

        setTimeout(() => {
            container.innerHTML = `
                <div class="scan-result ${riskClass}">
                    <div class="result-header">
                        <div class="result-title">
                            <i class="fas ${riskIcon}"></i>
                            Security Analysis Complete
                        </div>
                        <div class="risk-badge ${riskClass}">
                            ${result.category.toUpperCase()}
                        </div>
                    </div>
                    <div class="result-content">
                        <div class="risk-score-display">
                            <div class="score-value ${riskClass}">${result.risk_score}</div>
                            <div class="score-label">Risk Score</div>
                        </div>
                        <div class="result-meta">
                            <p><strong>Category:</strong> <span class="text-capitalize">${result.category}</span></p>
                            <p><strong>Scan Time:</strong> ${scanTime}ms</p>
                            ${result.explanation?.confidence ?
                                `<p><strong>Confidence:</strong> ${result.explanation.confidence}%</p>` : ''}
                        </div>
                        <div class="findings">
                            <h4>Security Findings:</h4>
                            <ul>
                                ${result.explanation.findings.map(finding => `<li>${finding}</li>`).join('')}
                            </ul>
                        </div>
                    </div>
                </div>
            `;

            requestAnimationFrame(() => {
                container.style.opacity = '1';
            });
        }, 150);
    }

    showResult(message, type) {
        const container = document.getElementById('demoResult');
        if (!container) return;

        container.style.opacity = '0';

        setTimeout(() => {
            container.innerHTML = `
                <div class="result-message ${type}">
                    <i class="fas fa-${type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    ${message}
                </div>
            `;

            requestAnimationFrame(() => {
                container.style.opacity = '1';
            });
        }, 150);
    }

    // ==========================================================================
    // 6. CONFIRMATION MODAL
    // ==========================================================================
    initConfirmationModal() {
        window.confirmationModal = new ConfirmationModal();
        console.log('✅ Confirmation modal initialized');
    }

    // ==========================================================================
    // 7. SMOOTH SCROLLING & NAVIGATION
    // ==========================================================================
    initSmoothScrolling() {
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function(e) {
                const targetId = this.getAttribute('href');
                if (targetId === '#') return;

                const target = document.querySelector(targetId);
                if (target) {
                    e.preventDefault();
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });

        console.log('✅ Smooth scrolling initialized');
    }

    initDashboardRedirect() {
        const dashboardButton = document.getElementById('dashboardButton');
        if (!dashboardButton) return;

        dashboardButton.addEventListener('click', (e) => {
            e.preventDefault();
            const token = localStorage.getItem('authToken');

            // Add click feedback
            dashboardButton.style.transform = 'scale(0.95)';
            setTimeout(() => {
                dashboardButton.style.transform = '';
            }, 150);

            setTimeout(() => {
                if (token) {
                    window.location.href = '/dashboard';
                } else {
                    window.location.href = '/login';
                }
            }, 300);
        });

        console.log('✅ Dashboard redirect initialized');
    }

    // ==========================================================================
    // 8. ENHANCED NOTIFICATION SYSTEM
    // ==========================================================================
    showNotification(message, type = 'info') {
        // Remove existing notifications
        const existingNotifications = document.querySelectorAll('.notification');
        existingNotifications.forEach(notif => {
            notif.style.transform = 'translateX(100%)';
            setTimeout(() => notif.remove(), 300);
        });

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-message">${message}</span>
                <button class="notification-close">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;

        // Add styles if not already present
        if (!document.querySelector('#notification-styles')) {
            const styles = document.createElement('style');
            styles.id = 'notification-styles';
            styles.textContent = `
                .notification {
                    position: fixed;
                    top: 100px;
                    right: 20px;
                    background: var(--bg-card);
                    border-left: 4px solid var(--primary-500);
                    border-radius: var(--radius-lg);
                    padding: 1rem 1.5rem;
                    box-shadow: var(--shadow-xl);
                    z-index: 10000;
                    max-width: 400px;
                    transform: translateX(100%);
                    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                }
                .notification.show {
                    transform: translateX(0);
                }
                .notification.success { border-left-color: var(--safe-color); }
                .notification.error { border-left-color: var(--malicious-color); }
                .notification.warning { border-left-color: var(--warning-color); }
                .notification-content {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    gap: 1rem;
                }
                .notification-close {
                    background: none;
                    border: none;
                    color: var(--text-muted);
                    cursor: pointer;
                    padding: 0.25rem;
                    border-radius: var(--radius-sm);
                    transition: all 0.2s ease;
                }
                .notification-close:hover {
                    background: var(--bg-secondary);
                    color: var(--text-primary);
                }
            `;
            document.head.appendChild(styles);
        }

        document.body.appendChild(notification);

        // Animate in
        requestAnimationFrame(() => {
            notification.classList.add('show');
        });

        // Add close event
        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 300);
        });

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.remove();
                    }
                }, 300);
            }
        }, 5000);
    }

    // ==========================================================================
    // 9. PERFORMANCE & INTERSECTION OBSERVER
    // ==========================================================================
    initIntersectionObserver() {
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                    observer.unobserve(entry.target);
                }
            });
        }, observerOptions);

        // Observe elements for scroll animations
        document.querySelectorAll('.fade-in-up').forEach(el => {
            observer.observe(el);
        });

        console.log('✅ Intersection observer initialized');
    }

    // ==========================================================================
    // 10. ERROR HANDLING & FALLBACKS
    // ==========================================================================
    initErrorHandling() {
        // Global error handler
        window.addEventListener('error', (e) => {
            console.error('Global error:', e.error);
        });

        // Promise rejection handler
        window.addEventListener('unhandledrejection', (e) => {
            console.error('Unhandled promise rejection:', e.reason);
        });

        // Network status monitoring
        window.addEventListener('online', () => {
            this.showNotification('Connection restored', 'success');
        });

        window.addEventListener('offline', () => {
            this.showNotification('You are currently offline', 'warning');
        });
    }
}

// ==========================================================================
// CONFIRMATION MODAL CLASS
// ==========================================================================
class ConfirmationModal {
    constructor() {
        this.modal = document.getElementById('confirmationModal');
        this.message = document.getElementById('confirmationMessage');
        this.confirmBtn = document.getElementById('confirmAction');
        this.cancelBtn = document.getElementById('confirmCancel');
        this.resolvePromise = null;
        this.init();
    }

    init() {
        // Set up event listeners
        this.confirmBtn.addEventListener('click', () => this.confirm());
        this.cancelBtn.addEventListener('click', () => this.cancel());

        // Close modal when clicking outside
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.cancel();
            }
        });

        // Close modal with Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && this.modal.classList.contains('active')) {
                this.cancel();
            }
        });
    }

    show(message, confirmText = 'Confirm', cancelText = 'Cancel', type = 'warning') {
        return new Promise((resolve) => {
            this.message.textContent = message;
            this.confirmBtn.innerHTML = `<i class="fas fa-check"></i> ${confirmText}`;
            this.cancelBtn.innerHTML = `<i class="fas fa-times"></i> ${cancelText}`;

            // Set button style based on type
            this.confirmBtn.className = `btn ${this.getButtonClass(type)}`;

            this.resolvePromise = resolve;
            this.modal.classList.add('active');

            // Focus the cancel button for accessibility
            this.cancelBtn.focus();
        });
    }

    getButtonClass(type) {
        const classes = {
            warning: 'btn-warning',
            danger: 'btn-danger',
            primary: 'btn-primary',
            success: 'btn-success'
        };
        return classes[type] || 'btn-danger';
    }

    confirm() {
        if (this.resolvePromise) {
            this.resolvePromise(true);
            this.resolvePromise = null;
        }
        this.hide();
    }

    cancel() {
        if (this.resolvePromise) {
            this.resolvePromise(false);
            this.resolvePromise = null;
        }
        this.hide();
    }

    hide() {
        this.modal.classList.remove('active');
    }
}

// ==========================================================================
// GLOBAL FUNCTIONS
// ==========================================================================

// Initialize the application
window.aipifLandingPage = new AIPIFLandingPage();

// Global function to check auth status
window.checkAuthStatus = function() {
    if (window.aipifLandingPage) {
        window.aipifLandingPage.checkAuthStatus();
    }
};

// Global function to show notifications
window.showNotification = function(message, type = 'info') {
    if (window.aipifLandingPage) {
        window.aipifLandingPage.showNotification(message, type);
    }
};

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        checkAuthStatus: window.checkAuthStatus,
        showNotification: window.showNotification
    };
}