// AIPIF Theme Manager - Synchronized across all pages
class AIPIFThemeManager {
    constructor() {
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        this.init();
    }

    init() {
        this.applyTheme(this.currentTheme);
        this.setupEventListeners();
        console.log('🎨 Theme Manager initialized - Current theme:', this.currentTheme);
    }

    applyTheme(theme) {
        console.log('🎨 Applying theme:', theme);
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        localStorage.setItem('theme', theme);

        // Update theme toggle buttons
        this.updateThemeToggles();

        // Dispatch event for other components to sync
        window.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme: theme }
        }));
    }

    updateThemeToggles() {
        const toggles = document.querySelectorAll('.theme-toggle, #themeToggle');
        console.log('🔄 Updating theme toggles. Found:', toggles.length);

        toggles.forEach(toggle => {
            const icon = toggle.querySelector('.theme-icon, i');
            const text = toggle.querySelector('.theme-text, span:not(.theme-icon)');

            if (this.currentTheme === 'dark') {
                if (icon) {
                    if (icon.tagName === 'I') {
                        icon.className = 'fas fa-sun';
                    } else {
                        icon.innerHTML = '<i class="fas fa-sun"></i>';
                    }
                }
                if (text) text.textContent = 'Light Mode';
            } else {
                if (icon) {
                    if (icon.tagName === 'I') {
                        icon.className = 'fas fa-moon';
                    } else {
                        icon.innerHTML = '<i class="fas fa-moon"></i>';
                    }
                }
                if (text) text.textContent = 'Dark Mode';
            }
        });
    }

    toggleTheme() {
        console.log('🔄 Toggling theme from', this.currentTheme);
        const newTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        this.applyTheme(newTheme);
    }

    setupEventListeners() {
        console.log('🔧 Setting up theme event listeners');

        // Listen for theme changes from other tabs/pages
        window.addEventListener('storage', (e) => {
            if (e.key === 'theme') {
                console.log('📡 Storage event detected - Theme changed in another tab:', e.newValue);
                if (e.newValue !== this.currentTheme) {
                    this.applyTheme(e.newValue);
                }
            }
        });

        // Listen for theme change events from other components
        window.addEventListener('themeChanged', (e) => {
            console.log('📡 ThemeChanged event detected:', e.detail.theme);
            if (e.detail.theme !== this.currentTheme) {
                this.applyTheme(e.detail.theme);
            }
        });

        // Add click event to all theme toggle buttons
        document.addEventListener('click', (e) => {
            const toggle = e.target.closest('.theme-toggle') || e.target.closest('#themeToggle');
            if (toggle) {
                e.preventDefault();
                e.stopPropagation();
                console.log('🎯 Theme toggle button clicked!');
                this.toggleTheme();
                return false;
            }
        });
    }
}

// Custom Confirmation Modal Manager
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
            warning: 'btn-danger',
            danger: 'btn-danger',
            primary: 'btn-primary',
            success: 'btn-primary'
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

// Dashboard JavaScript - REAL DATA ONLY VERSION
class AIPIFDashboard {
    constructor() {
        this.apiBase='';
        this.csrfToken = null;
        this.logsOffset = 0;
        this.logsLimit = 20;
        this.charts = {};
        this.scanCount = 0;
        this.totalThreats = 0;
        this.totalScanTime = 0;
        this.isInitialized = false;
        this.chartJsLoaded = false;
        this.mobileMenuOpen = false;

        // Theme manager will be set in init()
        this.themeManager = null;
    }

    init() {
        console.log('🚀 Initializing AIPIF Dashboard with REAL DATA...');

        // Initialize theme manager reference
        this.themeManager = window.themeManager;

        // Initialize confirmation modal
        window.confirmationModal = new ConfirmationModal();

        this.initializeCSRFToken();
        this.setupLogoutButtons();

        // Initialize components
        this.initMobileMenu();
        this.initEventListeners();

        // Show loading states
        this.showLoadingStates();

        // Load real data from API
        this.loadOverviewData();

        // Set initial page
        this.switchPage('overview');

        this.isInitialized = true;
        console.log('✅ Dashboard initialized with real data only');
    }

    setupLogoutButtons() {
        const logoutButtons = document.querySelectorAll('.logout-btn');

        logoutButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                this.confirmLogout();
            });
        });
    }

    async confirmLogout() {
        const confirmed = await window.confirmationModal.show(
            'Are you sure you want to logout? You will need to login again to access the dashboard.',
            'Logout',
            'Stay Logged In',
            'warning'
        );

        if (confirmed) {
            this.logout();
        }
    }

    logout() {
        // Clear auth data
        localStorage.removeItem('authToken');
        localStorage.removeItem('userData');
        localStorage.removeItem('theme');

        // Redirect to login page
        window.location.href = '/login';
    }

    showLoadingStates() {
        console.log('📱 Showing loading states...');

        // Show loading for stats
        const statsGrid = document.querySelector('.stats-grid');
        if (statsGrid) {
            const statCards = statsGrid.querySelectorAll('.stat-card');
            statCards.forEach(card => {
                const value = card.querySelector('.stat-value');
                if (value) {
                    const originalContent = value.innerHTML;
                    value.setAttribute('data-original', originalContent);
                    value.innerHTML = '<div class="loading-pulse" style="width: 60px; height: 32px;"></div>';
                }
            });
        }

        // Show loading for activity
        const activityContainer = document.getElementById('recentActivity');
        if (activityContainer && !activityContainer.querySelector('.loading-state')) {
            const originalContent = activityContainer.innerHTML;
            activityContainer.setAttribute('data-original', originalContent);
            activityContainer.innerHTML = `
                <div class="loading-state">
                    <div class="spinner"></div>
                    <p>Loading recent activity...</p>
                </div>
            `;
        }

        // Show loading for charts
        const chartsSection = document.querySelector('.charts-section');
        if (chartsSection) {
            const charts = chartsSection.querySelectorAll('.chart-container');
            charts.forEach(chart => {
                if (!chart.querySelector('.loading-pulse')) {
                    const originalContent = chart.innerHTML;
                    chart.setAttribute('data-original', originalContent);
                    chart.innerHTML = '<div class="loading-pulse" style="height: 100%;"></div>';
                }
            });
        }
    }

    restoreOriginalContent() {
        // Restore original content from data-original attributes
        const elements = document.querySelectorAll('[data-original]');
        elements.forEach(element => {
            const originalContent = element.getAttribute('data-original');
            if (originalContent) {
                element.innerHTML = originalContent;
                element.removeAttribute('data-original');
            }
        });
    }

    async loadOverviewData() {
        try {
            console.log('📊 Loading REAL overview data from API...');

            // Load fresh data from API - REAL DATA ONLY
            const [logsResponse, healthResponse, statsResponse] = await Promise.all([
                this.fetchWithTimeout(`${this.apiBase}/api/logs?limit=1000`),
                this.fetchWithTimeout(`${this.apiBase}/api/health`),
                this.fetchWithTimeout(`${this.apiBase}/api/stats`)
            ]);

            // Process API responses - throw errors if any fail
            if (!logsResponse.ok) {
                throw new Error(`Logs API returned ${logsResponse.status}`);
            }
            if (!healthResponse.ok) {
                throw new Error(`Health API returned ${healthResponse.status}`);
            }

            const logsData = await logsResponse.json();
            const healthData = await healthResponse.json();
            const statsData = statsResponse.ok ? await statsResponse.json() : {};

            console.log(`📈 Loaded ${logsData.logs?.length || 0} real log entries from API`);

            // Update UI with real API data
            this.updateUIWithRealData(logsData, statsData, healthData);

        } catch (error) {
            console.error('❌ Error loading REAL overview data:', error);
            this.showApiErrorStates();
            this.showNotification('Failed to load dashboard data from API. Please ensure backend is running.', 'error');
        }
    }

    updateUIWithRealData(logsData, statsData, healthData) {
        try {
            // First restore original content structure
            this.restoreOriginalContent();

            // Then update with real API data
            this.updateOverviewStats(logsData, statsData);
            this.updateRecentActivity(logsData.logs);
            this.updateSystemStatus(healthData);

            // Initialize charts only if Chart.js is available
            if (typeof Chart !== 'undefined') {
                this.initCharts();
                this.updateChartsWithRealData(logsData.logs, statsData);
            } else {
                console.warn('Chart.js not available, skipping charts');
            }
        } catch (error) {
            console.error('❌ Error updating UI with real data:', error);
        }
    }

    updateOverviewStats(data, stats) {
        try {
            const totalScans = document.getElementById('totalScans');
            const blockedAttacks = document.getElementById('blockedAttacks');
            const avgRisk = document.getElementById('avgRisk');
            const threatLevel = document.getElementById('threatLevel');
            const threatDescription = document.getElementById('threatDescription');

            // Calculate statistics from REAL API data only
            const totalRequests = data.total || (data.logs ? data.logs.length : 0);
            const blockedRequests = this.calculateBlockedRequests(data.logs);
            const averageRiskScore = this.calculateAverageRisk(data.logs);

            if (totalScans) totalScans.textContent = totalRequests.toLocaleString();
            if (blockedAttacks) blockedAttacks.textContent = blockedRequests.toLocaleString();
            if (avgRisk) avgRisk.textContent = averageRiskScore.toFixed(1);

            if (threatLevel && threatDescription) {
                if (averageRiskScore >= 70) {
                    threatLevel.innerHTML = '<i class="fas fa-skull-crossbones"></i> High';
                    threatLevel.className = 'threat-level malicious';
                    threatDescription.textContent = 'Elevated threat level detected';
                } else if (averageRiskScore >= 30) {
                    threatLevel.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Medium';
                    threatLevel.className = 'threat-level suspicious';
                    threatDescription.textContent = 'Moderate security activity';
                } else {
                    threatLevel.innerHTML = '<i class="fas fa-check-circle"></i> Low';
                    threatLevel.className = 'threat-level safe';
                    threatDescription.textContent = 'No active threats detected';
                }
            }
        } catch (error) {
            console.error('❌ Error updating overview stats:', error);
        }
    }

    calculateBlockedRequests(logs) {
        if (!logs || logs.length === 0) return 0;
        return logs.filter(log =>
            log.action === 'blocked' || (log.risk_score && log.risk_score >= 70)
        ).length;
    }

    calculateAverageRisk(logs) {
        if (!logs || logs.length === 0) return 0;
        const totalRisk = logs.reduce((sum, log) => sum + (log.risk_score || 0), 0);
        return totalRisk / logs.length;
    }

    updateRecentActivity(logs) {
        try {
            const container = document.getElementById('recentActivity');
            if (!container) return;

            const recentLogs = (logs || []).slice(0, 5);

            if (recentLogs.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-inbox"></i>
                        <h4>No Recent Activity</h4>
                        <p>No security events recorded in the database</p>
                    </div>
                `;
                return;
            }

            container.innerHTML = recentLogs.map(log => `
                <div class="activity-item">
                    <div class="activity-icon ${this.getRiskClass(log.risk_score)}">
                        <i class="fas ${this.getRiskIcon(log.risk_score)}"></i>
                    </div>
                    <div class="activity-content">
                        <div class="activity-title">${this.getActionText(log.action, log.risk_score)}</div>
                        <div class="activity-description">${log.prompt?.substring(0, 100) || 'No prompt'}...</div>
                    </div>
                    <div class="activity-time">${this.formatTime(log.timestamp)}</div>
                </div>
            `).join('');
        } catch (error) {
            console.error('❌ Error updating recent activity:', error);
        }
    }

    updateSystemStatus(healthData) {
        try {
            const statusBadge = document.getElementById('systemStatus');
            const lastUpdate = document.getElementById('lastUpdate');

            if (statusBadge) {
                const dot = statusBadge.querySelector('.status-dot');
                const text = statusBadge.querySelector('span');

                if (healthData.status === 'healthy') {
                    if (dot) dot.style.background = '#10b981';
                    if (text) text.textContent = 'System Online';
                } else {
                    if (dot) dot.style.background = '#ef4444';
                    if (text) text.textContent = 'System Issues';
                }
            }

            if (lastUpdate) {
                lastUpdate.innerHTML = `<i class="fas fa-sync-alt"></i> Updated ${new Date().toLocaleTimeString()}`;
            }
        } catch (error) {
            console.error('❌ Error updating system status:', error);
        }
    }

    // MOBILE MENU FUNCTIONALITY - FIXED VERSION
    initMobileMenu() {
        console.log('📱 Initializing mobile menu for dashboard...');

        try {
            // Create mobile menu toggle button if it doesn't exist
            if (!document.querySelector('.mobile-menu-toggle')) {
                this.menuToggle = document.createElement('button');
                this.menuToggle.className = 'mobile-menu-toggle';
                this.menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
                this.menuToggle.setAttribute('aria-label', 'Toggle menu');

                // Insert at the beginning of the main content for dashboard
                const mainContent = document.querySelector('.main-content');
                if (mainContent) {
                    mainContent.insertBefore(this.menuToggle, mainContent.firstChild);
                } else {
                    document.body.appendChild(this.menuToggle);
                }
                console.log('✅ Mobile menu toggle created for dashboard');
            } else {
                this.menuToggle = document.querySelector('.mobile-menu-toggle');
                console.log('✅ Mobile menu toggle found in dashboard');
            }

            // Create mobile overlay if it doesn't exist
            if (!document.querySelector('.mobile-overlay')) {
                this.overlay = document.createElement('div');
                this.overlay.className = 'mobile-overlay';
                document.body.appendChild(this.overlay);
                console.log('✅ Mobile overlay created for dashboard');
            } else {
                this.overlay = document.querySelector('.mobile-overlay');
                console.log('✅ Mobile overlay found in dashboard');
            }

            this.bindMobileMenuEvents();
            console.log('✅ Mobile menu initialized successfully for dashboard');

        } catch (error) {
            console.warn('⚠️ Mobile menu initialization failed in dashboard:', error);
        }
    }

    bindMobileMenuEvents() {
        if (!this.menuToggle || !this.overlay) {
            console.warn('⚠️ Mobile menu elements not found in dashboard');
            return;
        }

        console.log('🔧 Binding mobile menu events for dashboard...');

        // Toggle menu when button is clicked
        this.menuToggle.addEventListener('click', () => {
            console.log('📱 Mobile menu toggle clicked in dashboard');
            this.toggleMobileMenu();
        });

        // Close menu when overlay is clicked
        this.overlay.addEventListener('click', () => {
            console.log('📱 Mobile overlay clicked in dashboard');
            this.closeMobileMenu();
        });

        // Close menu when nav items are clicked
        document.querySelectorAll('.nav-item').forEach(item => {
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

        console.log('✅ Mobile menu events bound successfully for dashboard');
    }

    toggleMobileMenu() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) {
            console.warn('⚠️ Sidebar not found for mobile menu in dashboard');
            return;
        }

        if (this.mobileMenuOpen) {
            this.closeMobileMenu();
        } else {
            this.openMobileMenu();
        }
    }

    openMobileMenu() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        console.log('📱 Opening mobile menu in dashboard');
        sidebar.classList.add('mobile-open');
        this.overlay.classList.add('active');
        this.menuToggle.innerHTML = '<i class="fas fa-times"></i>';
        this.menuToggle.style.zIndex = '1002';
        document.body.style.overflow = 'hidden';
        this.mobileMenuOpen = true;
    }

    closeMobileMenu() {
        const sidebar = document.querySelector('.sidebar');
        if (!sidebar) return;

        console.log('📱 Closing mobile menu in dashboard');
        sidebar.classList.remove('mobile-open');
        this.overlay.classList.remove('active');
        this.menuToggle.innerHTML = '<i class="fas fa-bars"></i>';
        this.menuToggle.style.zIndex = '1001';
        document.body.style.overflow = '';
        this.mobileMenuOpen = false;
    }

    handleResize() {
        if (window.innerWidth > 768 && this.mobileMenuOpen) {
            console.log('📱 Window resized to desktop, closing mobile menu');
            this.closeMobileMenu();
        }
    }

    initEventListeners() {
        console.log('🔧 Setting up event listeners...');

        // Safe event listener initialization
        try {
            // Navigation items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', (e) => {
                    e.preventDefault();
                    const page = item.getAttribute('data-page');
                    if (page) {
                        this.switchPage(page);
                    }
                });
            });

            this.initScannerEvents();
            this.initLogsEvents();

            // View all links
            document.querySelectorAll('.view-all').forEach(link => {
                link.addEventListener('click', (e) => {
                    e.preventDefault();
                    const page = link.getAttribute('data-page');
                    if (page) {
                        this.switchPage(page);
                    }
                });
            });

            // Time selector
            const timeSelector = document.getElementById('requestsTimeRange');
            if (timeSelector) {
                timeSelector.addEventListener('change', () => this.loadOverviewData());
            }

            console.log('✅ Event listeners initialized');
        } catch (error) {
            console.error('❌ Error initializing event listeners:', error);
        }
    }

    initScannerEvents() {
        try {
            const scanButton = document.getElementById('scanButton');
            if (scanButton) {
                scanButton.addEventListener('click', () => this.scanPrompt());
            }

            const clearButton = document.getElementById('clearScannerButton');
            if (clearButton) {
                clearButton.addEventListener('click', () => this.clearScanner());
            }

            const scanTextarea = document.getElementById('scanPrompt');
            if (scanTextarea) {
                scanTextarea.addEventListener('keydown', (e) => {
                    if (e.key === 'Enter' && e.ctrlKey) {
                        e.preventDefault();
                        this.scanPrompt();
                    }
                });
            }
        } catch (error) {
            console.warn('⚠️ Scanner events initialization failed:', error);
        }
    }

    initLogsEvents() {
        try {
            const logSearch = document.getElementById('logSearch');
            if (logSearch) {
                logSearch.addEventListener('input', this.debounce(() => this.loadLogs(), 300));
            }

            const logFilter = document.getElementById('logFilter');
            if (logFilter) {
                logFilter.addEventListener('change', () => this.loadLogs());
            }

            const clearLogsBtn = document.getElementById('clearLogsBtn');
            if (clearLogsBtn) {
                clearLogsBtn.addEventListener('click', () => this.confirmClearLogs());
            }

            // Fix: Remove duplicate event listeners that were causing conflicts
            const prevBtn = document.getElementById('prevLogsBtn');
            const nextBtn = document.getElementById('nextLogsBtn');

            // Remove existing click listeners to prevent duplicates
            const newPrevBtn = prevBtn.cloneNode(true);
            const newNextBtn = nextBtn.cloneNode(true);

            if (prevBtn && prevBtn.parentNode) {
                prevBtn.parentNode.replaceChild(newPrevBtn, prevBtn);
                newPrevBtn.addEventListener('click', () => this.loadPreviousLogs());
            }

            if (nextBtn && nextBtn.parentNode) {
                nextBtn.parentNode.replaceChild(newNextBtn, nextBtn);
                newNextBtn.addEventListener('click', () => this.loadNextLogs());
            }

        } catch (error) {
            console.warn('⚠️ Logs events initialization failed:', error);
        }
    }

    async confirmClearLogs() {
        const confirmed = await window.confirmationModal.show(
            'Are you sure you want to clear ALL security logs? This action cannot be undone and all log data will be permanently deleted.',
            'Clear All Logs',
            'Cancel',
            'danger'
        );

        if (confirmed) {
            this.clearLogs();
        }
    }

    switchPage(page) {
        console.log(`🔄 Switching to page: ${page}`);

        try {
            // Update active nav item
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });

            const activeNav = document.querySelector(`[data-page="${page}"]`);
            if (activeNav) {
                activeNav.classList.add('active');
            }

            // Hide all pages and show target page
            document.querySelectorAll('.page').forEach(pageEl => {
                pageEl.classList.remove('active');
            });

            const targetPage = document.getElementById(`${page}Page`);
            if (targetPage) {
                targetPage.classList.add('active');
            }

            // Load page-specific data
            switch(page) {
                case 'overview':
                    this.loadOverviewData();
                    break;
                case 'logs':
                    this.loadLogs();
                    break;
                case 'scanner':
                    this.clearScanner();
                    break;
            }

            // Close mobile menu on page switch
            this.closeMobileMenu();
            console.log(`✅ Switched to ${page} page`);
        } catch (error) {
            console.error(`❌ Error switching to page ${page}:`, error);
        }
    }

    initCharts() {
        console.log('📊 Initializing charts...');

        try {
            Object.values(this.charts).forEach(chart => {
                if (chart && typeof chart.destroy === 'function') {
                    chart.destroy();
                }
            });

            this.charts = {};

            if (typeof Chart !== 'undefined') {
                this.renderRequestsChart();
                this.renderThreatsChart();
                this.chartJsLoaded = true;
            } else {
                console.warn('Chart.js not fully loaded - charts will not be available');
                this.chartJsLoaded = false;
            }
        } catch (error) {
            console.error('❌ Error initializing charts:', error);
            this.chartJsLoaded = false;
        }
    }

    renderRequestsChart() {
        try {
            const canvas = document.getElementById('requestsChart');
            if (!canvas) {
                console.log('❌ Requests chart canvas not found');
                return;
            }

            const ctx = canvas.getContext('2d');
            const isDark = this.themeManager?.currentTheme === 'dark';
            const gridColor = isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
            const textColor = isDark ? '#f8fafc' : '#0f172a';

            // Initialize with empty data - will be populated with real data
            const data = {
                labels: [],
                datasets: [
                    {
                        label: 'Total Requests',
                        data: [],
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 3
                    },
                    {
                        label: 'Blocked Requests',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        fill: true,
                        tension: 0.4,
                        borderWidth: 3
                    }
                ]
            };

            this.charts.requests = new Chart(ctx, {
                type: 'line',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: {
                                color: textColor,
                                usePointStyle: true,
                                padding: 20
                            }
                        },
                        tooltip: {
                            mode: 'index',
                            intersect: false,
                            backgroundColor: isDark ? '#1e293b' : '#ffffff',
                            titleColor: textColor,
                            bodyColor: textColor,
                            borderColor: isDark ? '#334155' : '#e2e8f0'
                        }
                    },
                    scales: {
                        x: {
                            grid: {
                                color: gridColor
                            },
                            ticks: {
                                color: textColor
                            }
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: gridColor
                            },
                            ticks: {
                                color: textColor
                            }
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Failed to create requests chart:', error);
        }
    }

    renderThreatsChart() {
        try {
            const canvas = document.getElementById('threatsChart');
            if (!canvas) {
                console.log('❌ Threats chart canvas not found');
                return;
            }

            const ctx = canvas.getContext('2d');
            const isDark = this.themeManager?.currentTheme === 'dark';
            const textColor = isDark ? '#f8fafc' : '#0f172a';

            // Initialize with empty data - will be populated with real data
            const data = {
                labels: ['Safe', 'Suspicious', 'Malicious'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderWidth: 2,
                    hoverOffset: 15
                }]
            };

            this.charts.threats = new Chart(ctx, {
                type: 'doughnut',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '60%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: textColor,
                                usePointStyle: true,
                                padding: 20,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        tooltip: {
                            backgroundColor: isDark ? '#1e293b' : '#ffffff',
                            titleColor: textColor,
                            bodyColor: textColor,
                            borderColor: isDark ? '#334155' : '#e2e8f0'
                        }
                    }
                }
            });
        } catch (error) {
            console.error('Failed to create threats chart:', error);
        }
    }

    updateChartsWithRealData(logs, stats) {
        if (!this.chartJsLoaded) {
            console.warn('Chart.js not loaded, skipping chart updates');
            return;
        }

        console.log('📈 Updating charts with real data...', { logsCount: logs?.length });

        try {
            if (this.charts.threats && logs && logs.length > 0) {
                this.updateThreatsChart(logs);
            } else if (this.charts.threats) {
                // If no logs, show empty state
                this.charts.threats.data.datasets[0].data = [0, 0, 0];
                this.charts.threats.update();
            }

            if (this.charts.requests && logs && logs.length > 0) {
                this.updateRequestsChart(logs);
            } else if (this.charts.requests) {
                // If no logs, show empty state
                this.charts.requests.data.datasets[0].data = [];
                this.charts.requests.data.datasets[1].data = [];
                this.charts.requests.update();
            }
        } catch (error) {
            console.error('❌ Error updating charts with real data:', error);
        }
    }

    updateThreatsChart(logs) {
        if (!this.charts.threats) return;

        try {
            const threatDistribution = this.calculateThreatDistribution(logs);
            const data = Object.values(threatDistribution);
            const colors = ['#10b981', '#f59e0b', '#ef4444'];

            this.charts.threats.data.datasets[0].data = data;
            this.charts.threats.data.datasets[0].backgroundColor = colors;
            this.charts.threats.data.datasets[0].borderColor = colors;
            this.charts.threats.update();

            console.log('✅ Threats chart updated with real data:', threatDistribution);
        } catch (error) {
            console.error('❌ Error updating threats chart:', error);
        }
    }

    calculateThreatDistribution(logs) {
        if (!logs || logs.length === 0) {
            return { safe: 0, suspicious: 0, malicious: 0 };
        }

        const distribution = { safe: 0, suspicious: 0, malicious: 0 };

        logs.forEach(log => {
            const riskScore = log.risk_score || 0;
            if (riskScore >= 70) {
                distribution.malicious++;
            } else if (riskScore >= 30) {
                distribution.suspicious++;
            } else {
                distribution.safe++;
            }
        });

        const total = logs.length;
        return {
            safe: Math.round((distribution.safe / total) * 100),
            suspicious: Math.round((distribution.suspicious / total) * 100),
            malicious: Math.round((distribution.malicious / total) * 100)
        };
    }

    updateRequestsChart(logs) {
        if (!this.charts.requests) return;

        try {
            const timeSeriesData = this.processTimeSeriesData(logs);
            this.charts.requests.data.labels = timeSeriesData.labels;
            this.charts.requests.data.datasets[0].data = timeSeriesData.totalRequests;
            this.charts.requests.data.datasets[1].data = timeSeriesData.blockedRequests;
            this.charts.requests.update();

            console.log('✅ Requests chart updated with real data:', timeSeriesData);
        } catch (error) {
            console.error('❌ Error updating requests chart:', error);
        }
    }

    processTimeSeriesData(logs) {
        const last7Days = this.getLast7Days();
        const dailyData = last7Days.map(day => ({
            date: day.date,
            label: day.label,
            total: 0,
            blocked: 0
        }));

        if (logs && logs.length > 0) {
            logs.forEach(log => {
                if (!log.timestamp) return;
                const logDate = new Date(log.timestamp).toISOString().split('T')[0];
                const dayData = dailyData.find(day => day.date === logDate);

                if (dayData) {
                    dayData.total++;
                    if (log.action === 'blocked' || (log.risk_score && log.risk_score >= 70)) {
                        dayData.blocked++;
                    }
                }
            });
        }

        return {
            labels: dailyData.map(day => day.label),
            totalRequests: dailyData.map(day => day.total),
            blockedRequests: dailyData.map(day => day.blocked)
        };
    }

    getLast7Days() {
        const days = [];
        const today = new Date();

        for (let i = 6; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(date.getDate() - i);
            const dateString = date.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric'
            });

            days.push({
                date: date.toISOString().split('T')[0],
                label: dateString
            });
        }

        return days;
    }

    async getCSRFToken() {
        try {
            const token = localStorage.getItem('authToken');
            if (!token) {
                console.warn('⚠️ No auth token found for CSRF request');
                throw new Error('No authentication token. Please login again.');
            }

            console.log('🔐 Requesting CSRF token...');

            const response = await fetch(`${this.apiBase}/api/csrf-token`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            console.log('🔐 CSRF token response status:', response.status);

            if (!response.ok) {
                let errorText = 'CSRF token request failed';
                try {
                    const errorData = await response.json();
                    errorText = errorData.detail || errorText;
                } catch (e) {
                    errorText = `HTTP ${response.status}: ${response.statusText}`;
                }

                console.error('❌ CSRF token request failed:', errorText);

                if (response.status === 401) {
                    this.showNotification('Session expired. Please login again.', 'error');
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 2000);
                    return null;
                }

                throw new Error(errorText);
            }

            const data = await response.json();
            this.csrfToken = data.csrf_token;
            console.log('✅ CSRF token obtained');
            return this.csrfToken;

        } catch (error) {
            console.error('❌ Failed to get CSRF token:', error);
            this.showNotification('Failed to get security token. Please refresh the page.', 'error');
            return null;
        }
    }

    async makeCSRFRequest(url, options = {}) {
        try {
            console.log('🔐 Making CSRF-protected request to:', url, 'Method:', options.method);

            // Ensure we have a CSRF token
            if (!this.csrfToken) {
                console.log('🔐 No CSRF token, getting one...');
                const tokenResult = await this.getCSRFToken();
                if (!tokenResult) {
                    throw new Error('Could not obtain CSRF token');
                }
            }

            // Get auth token from localStorage
            const authToken = localStorage.getItem('authToken');
            if (!authToken) {
                throw new Error('No authentication token found. Please login again.');
            }

            console.log('🔐 Auth token exists:', !!authToken);
            console.log('🔐 CSRF token exists:', !!this.csrfToken);

            // Prepare headers
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authToken}`,
                ...(this.csrfToken && { 'X-CSRF-Token': this.csrfToken })
            };

            const fetchOptions = {
                ...options,
                headers: headers
            };

            console.log('🔐 Starting fetch request...');
            const response = await fetch(url, fetchOptions);
            console.log('🔐 Fetch completed, status:', response.status, response.statusText);

            // Handle CSRF token refresh if we get a 403
            if (response.status === 403 && this.csrfToken) {
                console.log('🔄 CSRF token might be expired, trying to refresh...');
                this.csrfToken = null;

                // Try one more time with a new token
                const retryToken = await this.getCSRFToken();
                if (retryToken) {
                    console.log('🔄 Retrying request with new CSRF token...');
                    fetchOptions.headers['X-CSRF-Token'] = retryToken;
                    const retryResponse = await fetch(url, fetchOptions);
                    return retryResponse;
                }
            }

            return response;

        } catch (error) {
            console.error('❌ Fetch request failed:', error);

            if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
                console.error('❌ Network error - check if server is running on', this.apiBase);
                this.showNotification('Cannot connect to server. Please ensure the backend is running.', 'error');
            } else {
                this.showNotification('Request failed: ' + error.message, 'error');
            }

            throw error;
        }
    }

    async initializeCSRFToken() {
        try {
            await this.getCSRFToken();
            console.log('🔐 CSRF protection initialized');
        } catch (error) {
            console.warn('⚠️ CSRF token initialization failed:', error);
        }
    }

    async scanPrompt() {
        const promptInput = document.getElementById('scanPrompt');
        const resultContainer = document.getElementById('scanResult');
        const scanButton = document.getElementById('scanButton');

        if (!promptInput || !resultContainer) {
            this.showNotification('Scanner components not found', 'error');
            return;
        }

        const prompt = promptInput.value.trim();
        if (!prompt) {
            this.showNotification('Please enter a prompt to scan', 'warning');
            promptInput.focus();
            return;
        }

        try {
            scanButton.disabled = true;
            scanButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';

            resultContainer.innerHTML = `
                <div class="result-loading">
                    <div class="spinner"></div>
                    <h4>Analyzing Prompt Security...</h4>
                    <p>Checking for injection attempts and malicious patterns</p>
                </div>
            `;

            const startTime = Date.now();

            // REAL API CALL ONLY - NO SIMULATION
            const response = await this.makeCSRFRequest(`${this.apiBase}/api/scan`, {
                method: 'POST',
                body: JSON.stringify({ prompt })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`API returned ${response.status}: ${response.statusText}. ${errorText}`);
            }

            const result = await response.json();
            const scanTime = Date.now() - startTime;

            this.displayScanResult(result, scanTime);

            // Update local stats with REAL scan data
            this.scanCount++;
            if (result.risk_score >= 30) this.totalThreats++;
            this.totalScanTime += scanTime;
            this.updateScannerStats();

            const riskLevel = result.risk_score >= 70 ? 'High risk' :
                            result.risk_score >= 30 ? 'Medium risk' : 'Safe';
            this.showNotification(`Scan complete: ${riskLevel} detected`, 'success');

            // Refresh dashboard to show new scan data
            setTimeout(() => this.loadOverviewData(), 1000);

        } catch (error) {
            console.error('❌ REAL Scan error:', error);

            if (error.message.includes('CSRF') || error.message.includes('403')) {
                // Get new CSRF token and retry
                this.csrfToken = null;
                this.showNotification('Security token expired. Retrying...', 'warning');
                setTimeout(() => this.scanPrompt(), 1000);
                return;
            }

            this.displayScanError('Scan failed: ' + error.message);
            this.showNotification('Scan failed - API unavailable. Please ensure backend is running.', 'error');
        } finally {
            if (scanButton) {
                scanButton.disabled = false;
                scanButton.innerHTML = '<i class="fas fa-search"></i> Scan Prompt';
            }
        }
    }

    displayScanResult(result, scanTime) {
        const container = document.getElementById('scanResult');
        if (!container) return;

        try {
            const riskClass = this.getRiskClass(result.risk_score);
            const riskLabel = result.risk_score >= 70 ? 'High Risk' :
                             result.risk_score >= 30 ? 'Medium Risk' : 'Low Risk';
            const riskIcon = result.risk_score >= 70 ? 'fa-exclamation-triangle' :
                            result.risk_score >= 30 ? 'fa-info-circle' : 'fa-check-circle';

            const findings = result.explanation?.findings || ['No detailed analysis available'];

            container.innerHTML = `
                <div class="scan-result ${riskClass}">
                    <div class="result-header">
                        <div class="result-title">
                            <i class="fas ${riskIcon}"></i>
                            Security Analysis Complete
                        </div>
                        <div class="risk-badge ${riskClass}">
                            ${riskLabel}
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
                            ${result.model_used ?
                                `<p><strong>Model:</strong> ${result.model_used}</p>` : ''}
                        </div>
                        <div class="findings">
                            <h4>Security Findings:</h4>
                            <ul>
                                ${findings.map(finding => `<li>${finding}</li>`).join('')}
                            </ul>
                        </div>
                        ${result.recommendation ? `
                        <div class="recommendation">
                            <h4>Recommendation:</h4>
                            <p>${result.recommendation}</p>
                        </div>
                        ` : ''}
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('❌ Error displaying scan result:', error);
            this.displayScanError('Error displaying scan results');
        }
    }

    displayScanError(message) {
        const container = document.getElementById('scanResult');
        if (!container) return;

        container.innerHTML = `
            <div class="scan-result error">
                <div class="result-header">
                    <h4>Scan Failed</h4>
                    <div class="risk-badge malicious">Error</div>
                </div>
                <div class="result-content">
                    <p>${message}</p>
                    <p>Please check your backend connection and try again.</p>
                </div>
            </div>
        `;
    }

    clearScanner() {
        const promptInput = document.getElementById('scanPrompt');
        const resultContainer = document.getElementById('scanResult');

        if (promptInput) promptInput.value = '';
        if (resultContainer) {
            resultContainer.innerHTML = `
                <div class="result-placeholder">
                    <i class="fas fa-search"></i>
                    <h4>Ready to Scan</h4>
                    <p>Enter a prompt above to begin security analysis</p>
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

    async loadLogs() {
        try {
            const search = document.getElementById('logSearch')?.value || '';
            const filter = document.getElementById('logFilter')?.value || 'all';

            this.showLoading('logsTableBody', 'Loading security logs...');

            console.log('🔧 LOAD_LOGS: Starting...');

            // Use CSRF-protected request
            const response = await this.makeCSRFRequest(
                `${this.apiBase}/api/logs?limit=${this.logsLimit}&offset=${this.logsOffset}`
            );

            console.log('🔧 LOAD_LOGS: Response status:', response.status);

            if (!response.ok) {
                if (response.status === 401) {
                    this.showError('logsTableBody', 'Session expired. Please login again.');
                    setTimeout(() => {
                        window.location.href = '/login';
                    }, 2000);
                    return;
                } else if (response.status === 403) {
                    this.showError('logsTableBody', 'Permission denied. Please check your credentials.');
                    return;
                } else {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
            }

            const logsData = await response.json();
            console.log('✅ LOAD_LOGS: Success, loaded', logsData.logs?.length, 'logs');

            this.displayLogs(logsData.logs, search, filter);
            this.updatePagination(logsData.total);

        } catch (error) {
            console.error('❌ Error loading logs:', error);

            if (error.message.includes('Failed to fetch')) {
                this.showError('logsTableBody', 'Cannot connect to server. Please ensure the backend is running on ' + this.apiBase);
            } else if (error.message.includes('CSRF')) {
                this.showError('logsTableBody', 'Security token error. Please refresh the page.');
            } else {
                this.showError('logsTableBody', 'Failed to load logs: ' + error.message);
            }
        }
    }

    displayLogs(logs, search, filter) {
        const tbody = document.getElementById('logsTableBody');
        if (!tbody) return;

        try {
            let filteredLogs = logs || [];

            if (search) {
                filteredLogs = filteredLogs.filter(log =>
                    log.prompt?.toLowerCase().includes(search.toLowerCase()) ||
                    log.category?.toLowerCase().includes(search.toLowerCase()) ||
                    log.action?.toLowerCase().includes(search.toLowerCase())
                );
            }

            if (filter !== 'all') {
                filteredLogs = filteredLogs.filter(log => log.category === filter);
            }

            if (filteredLogs.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="no-data">
                            <i class="fas fa-inbox"></i>
                            <div>No logs found</div>
                            <small>${search || filter !== 'all' ? 'Try changing search/filter' : 'No log data available in database'}</small>
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = filteredLogs.map(log => `
                <tr>
                    <td>${this.formatTime(log.timestamp)}</td>
                    <td class="prompt-cell" title="${log.prompt || 'N/A'}">${log.prompt || 'N/A'}</td>
                    <td>
                        <span class="risk-badge ${this.getRiskClass(log.risk_score)}">
                            ${log.risk_score || 0}
                        </span>
                    </td>
                    <td>
                        <span class="category-badge ${log.category || 'safe'}">
                            ${this.capitalizeFirst(log.category || 'safe')}
                        </span>
                    </td>
                    <td>
                        <span class="action-badge ${log.action || 'allowed'}">
                            ${this.capitalizeFirst(log.action || 'allowed')}
                        </span>
                    </td>
                    <td>${log.user_ip || 'N/A'}</td>
                </tr>
            `).join('');
        } catch (error) {
            console.error('❌ Error displaying logs:', error);
            this.showError('logsTableBody', 'Error displaying logs');
        }
    }

    updatePagination(total) {
        const info = document.getElementById('paginationInfo');
        const prevBtn = document.getElementById('prevLogsBtn');
        const nextBtn = document.getElementById('nextLogsBtn');

        if (info && prevBtn && nextBtn) {
            const currentPage = Math.floor(this.logsOffset / this.logsLimit) + 1;
            const totalPages = Math.ceil(total / this.logsLimit) || 1;

            info.textContent = `Page ${currentPage} of ${totalPages}`;
            prevBtn.disabled = this.logsOffset === 0;
            nextBtn.disabled = (this.logsOffset + this.logsLimit) >= total;
        }
    }

    loadNextLogs() {
        this.logsOffset += this.logsLimit;
        this.loadLogs();
    }

    loadPreviousLogs() {
        this.logsOffset = Math.max(0, this.logsOffset - this.logsLimit);
        this.loadLogs();
    }

    async clearLogs() {
        console.log('🔧 CLEAR_LOGS: Starting clear logs process...');

        try {
            const clearLogsBtn = document.getElementById('clearLogsBtn');
            if (clearLogsBtn) {
                clearLogsBtn.disabled = true;
                clearLogsBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Clearing...';
            }

            console.log('🔧 CLEAR_LOGS: Getting CSRF token...');
            // Ensure we have a CSRF token
            if (!this.csrfToken) {
                await this.getCSRFToken();
            }

            console.log('🔧 CLEAR_LOGS: Sending DELETE request...');
            // Use makeCSRFRequest for authenticated DELETE
            const response = await this.makeCSRFRequest(`${this.apiBase}/api/logs`, {
                method: 'DELETE',
                body: JSON.stringify({
                    confirm: true,
                    filters: null
                })
            });

            console.log('🔧 CLEAR_LOGS: Response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('❌ CLEAR_LOGS: API error:', errorText);
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log('✅ CLEAR_LOGS: Success:', result);

            this.showNotification(`✅ ${result.message}`, 'success');

            // Reload data to show empty state
            setTimeout(() => {
                this.loadLogs();
                this.loadOverviewData();
            }, 1000);

        } catch (error) {
            console.error('❌ CLEAR_LOGS Error:', error);

            if (error.message.includes('CSRF') || error.message.includes('403')) {
                this.csrfToken = null;
                this.showNotification('🔐 Security token expired. Please try again.', 'warning');
                // Retry after getting new token
                setTimeout(() => this.clearLogs(), 1000);
            } else if (error.message.includes('401')) {
                this.showNotification('🔐 Please login again to clear logs.', 'error');
                // Redirect to login if unauthorized
                setTimeout(() => {
                    window.location.href = '/login';
                }, 2000);
            } else if (error.message.includes('429')) {
                this.showNotification('⏰ Rate limit exceeded. Please wait a moment.', 'warning');
            } else {
                this.showNotification('❌ Failed to clear logs: ' + error.message, 'error');
            }
        } finally {
            const clearLogsBtn = document.getElementById('clearLogsBtn');
            if (clearLogsBtn) {
                clearLogsBtn.disabled = false;
                clearLogsBtn.innerHTML = '<i class="fas fa-trash-alt"></i> Clear All Logs';
            }
        }
    }

    showApiErrorStates() {
        const activityContainer = document.getElementById('recentActivity');
        if (activityContainer) {
            activityContainer.innerHTML = `
                <div class="error-state">
                    <i class="fas fa-exclamation-circle"></i>
                    <h4>API Connection Error</h4>
                    <p>Unable to connect to backend API at ${this.apiBase}</p>
                    <p><small>Please ensure your backend server is running</small></p>
                    <button onclick="window.dashboard.loadOverviewData()" class="btn btn-sm">
                        <i class="fas fa-redo"></i> Retry
                    </button>
                </div>
            `;
        }

        const statsGrid = document.querySelector('.stats-grid');
        if (statsGrid) {
            statsGrid.innerHTML = `
                <div class="stat-card error">
                    <div class="stat-header">
                        <h3>Total Scans</h3>
                    </div>
                    <div class="stat-value">--</div>
                    <div class="stat-description">API unavailable</div>
                </div>
                <div class="stat-card error">
                    <div class="stat-header">
                        <h3>Blocked Attacks</h3>
                    </div>
                    <div class="stat-value">--</div>
                    <div class="stat-description">API unavailable</div>
                </div>
                <div class="stat-card error">
                    <div class="stat-header">
                        <h3>Avg Risk Score</h3>
                    </div>
                    <div class="stat-value">--</div>
                    <div class="stat-description">API unavailable</div>
                </div>
                <div class="stat-card error">
                    <div class="stat-header">
                        <h3>API Status</h3>
                    </div>
                    <div class="threat-level malicious">
                        <i class="fas fa-unlink"></i> Offline
                    </div>
                    <div class="stat-description">Backend not connected</div>
                </div>
            `;
        }

        // Clear charts on error
        Object.values(this.charts).forEach(chart => {
            if (chart && typeof chart.destroy === 'function') {
                chart.destroy();
            }
        });
        this.charts = {};
    }

    showNotification(message, type = 'info') {
        try {
            const existingNotifications = document.querySelectorAll('.notification');
            existingNotifications.forEach(notif => notif.remove());

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

            document.body.appendChild(notification);

            notification.querySelector('.notification-close').addEventListener('click', () => {
                notification.remove();
            });

            setTimeout(() => {
                if (notification.parentNode) {
                    notification.remove();
                }
            }, 5000);
        } catch (error) {
            console.error('❌ Error showing notification:', error);
        }
    }

    // Utility functions
    getRiskClass(score) {
        if (score >= 70) return 'malicious';
        if (score >= 30) return 'suspicious';
        return 'safe';
    }

    getRiskIcon(score) {
        if (score >= 70) return 'fa-exclamation-triangle';
        if (score >= 30) return 'fa-info-circle';
        return 'fa-check-circle';
    }

    getActionText(action, score) {
        if (action === 'blocked') return 'Threat Blocked';
        if (action === 'scanned') return 'Prompt Scanned';
        if (score >= 70) return 'High Risk Detected';
        if (score >= 30) return 'Suspicious Activity';
        return 'Safe Processing';
    }

    formatTime(timestamp) {
        if (!timestamp) return 'N/A';
        try {
            return new Date(timestamp).toLocaleString();
        } catch {
            return 'Invalid Date';
        }
    }

    capitalizeFirst(string) {
        if (!string) return '';
        return string.charAt(0).toUpperCase() + string.slice(1);
    }

    async fetchWithTimeout(url, options = {}, timeout = 5000) {
        const controller = new AbortController();
        const id = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(id);
            return response;
        } catch (error) {
            clearTimeout(id);
            throw error;
        }
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    showError(containerId, message) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = `
                <div class="error-state">
                    <i class="fas fa-exclamation-circle"></i>
                    <p>${message}</p>
                </div>
            `;
        }
    }

    showLoading(containerId, message) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = `
                <tr>
                    <td colspan="6" class="loading-state">
                        <div class="spinner"></div>
                        <p>${message}</p>
                    </td>
                </tr>
            `;
        }
    }
}

// Add CSS for loading states and notifications
const globalStyles = `
<style>
.loading-pulse {
    background: linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%);
    background-size: 200% 100%;
    animation: loading 1.5s infinite;
    border-radius: 4px;
}

[data-theme="dark"] .loading-pulse {
    background: linear-gradient(90deg, #334155 25%, #475569 50%, #334155 75%);
    background-size: 200% 100%;
}

.loading-state {
    text-align: center;
    padding: 2rem;
    color: #64748b;
}

.loading-state .spinner {
    border: 3px solid #f3f4f6;
    border-top: 3px solid #3b82f6;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin: 0 auto 1rem;
}

[data-theme="dark"] .loading-state .spinner {
    border: 3px solid #374151;
    border-top: 3px solid #60a5fa;
}

@keyframes loading {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    background: white;
    border-left: 4px solid #3b82f6;
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
    z-index: 1000;
    max-width: 400px;
    animation: slideIn 0.3s ease-out;
}

[data-theme="dark"] .notification {
    background: #1e293b;
    color: #f8fafc;
}

.notification.success {
    border-left-color: #10b981;
}

.notification.error {
    border-left-color: #ef4444;
}

.notification.warning {
    border-left-color: #f59e0b;
}

.notification-content {
    display: flex;
    justify-content: between;
    align-items: center;
    gap: 12px;
}

.notification-close {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    padding: 4px;
}

@keyframes slideIn {
    from {
        transform: translateX(100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

.theme-toggle {
    background: none;
    border: none;
    color: inherit;
    cursor: pointer;
    padding: 8px 12px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
    transition: background-color 0.2s;
}

.theme-toggle:hover {
    background: rgba(255, 255, 255, 0.1);
}

.stat-card.error {
    background: linear-gradient(135deg, var(--bg-secondary) 0%, rgba(239, 68, 68, 0.1) 100%);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.stat-card.error .stat-value {
    color: #ef4444;
    font-size: 1.5rem;
}

.error-state {
    text-align: center;
    padding: 2rem;
    color: #ef4444;
}

.error-state i {
    font-size: 3rem;
    margin-bottom: 1rem;
}

.result-loading {
    text-align: center;
    padding: 2rem;
    color: var(--text-secondary);
}

.result-loading .spinner {
    border: 3px solid var(--border-color);
    border-top: 3px solid var(--primary-color);
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 1s linear infinite;
    margin: 0 auto 1rem;
}

.text-capitalize {
    text-transform: capitalize;
}

.result-meta {
    background: var(--bg-secondary);
    padding: 1rem;
    border-radius: var(--border-radius);
    margin: 1rem 0;
}

.result-meta p {
    margin: 0.5rem 0;
}

.recommendation {
    background: var(--bg-secondary);
    padding: 1rem;
    border-radius: var(--border-radius);
    margin-top: 1rem;
    border-left: 4px solid var(--primary-color);
}

/* Mobile Overlay Animation */
.mobile-overlay {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.7);
    z-index: 998;
    backdrop-filter: blur(4px);
}

.mobile-overlay.active {
    display: block;
}

/* Mobile Menu Toggle Button */
.mobile-menu-toggle {
    display: none;
    position: fixed;
    top: 1.5rem;
    left: 1.5rem;
    z-index: 1001;
    background: linear-gradient(135deg, var(--primary-500), var(--primary-700));
    color: white;
    border: none;
    border-radius: 12px;
    width: 44px;
    height: 44px;
    cursor: pointer;
    font-size: 1.1rem;
    transition: all 0.3s ease;
    box-shadow: var(--shadow-md);
    align-items: center;
    justify-content: center;
}

.mobile-menu-toggle:hover {
    transform: translateY(-2px);
    box-shadow: var(--shadow-lg);
}

/* Mobile navigation styles */
@media (max-width: 768px) {
    .mobile-menu-toggle {
        display: flex;
    }

    /* Sidebar mobile styles */
    .sidebar {
        position: fixed;
        top: 0;
        left: -280px;
        width: 280px;
        height: 100vh;
        background: var(--bg-card);
        transition: left 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        z-index: 999;
        box-shadow: 2px 0 20px rgba(0, 0, 0, 0.3);
        border-right: 1px solid var(--border-light);
    }

    .sidebar.mobile-open {
        left: 0;
    }

    /* Ensure main content doesn't shift */
    .main-content {
        margin-left: 0 !important;
    }
}
</style>
`;

// Inject global styles
document.head.insertAdjacentHTML('beforeend', globalStyles);

// Universal initialization for all pages
document.addEventListener('DOMContentLoaded', function() {
    try {
        console.log('🎯 Starting AIPIF initialization...');

        // Initialize theme manager for all pages - SINGLE INSTANCE
        window.themeManager = new AIPIFThemeManager();

        // Check if we're on the dashboard page
        const isDashboardPage = document.querySelector('.dashboard-container') !== null;

        if (isDashboardPage) {
            console.log('📊 Dashboard page detected - initializing dashboard...');
            // Initialize dashboard
            window.dashboard = new AIPIFDashboard();
            window.dashboard.init();
        } else {
            console.log('🏠 Landing page detected - theme only initialization');
            // For landing page, just theme manager is enough
        }

        console.log('🎉 AIPIF initialized successfully!');

    } catch (error) {
        console.error('💥 Failed to initialize AIPIF:', error);

        // Show user-friendly error
        const mainContent = document.querySelector('.main-content, .landing-container');
        if (mainContent) {
            mainContent.innerHTML = `
                <div class="error-state" style="padding: 2rem; text-align: center;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: #ef4444; margin-bottom: 1rem;"></i>
                    <h2>Initialization Failed</h2>
                    <p>There was an error loading the page. Please refresh.</p>
                    <button onclick="location.reload()" class="btn btn-primary" style="margin-top: 1rem;">
                        <i class="fas fa-redo"></i> Reload Page
                    </button>
                </div>
            `;
        }
    }
});

// Global functions available on all pages
function toggleTheme() {
    window.themeManager?.toggleTheme();
}

// Dashboard-specific global functions (only work on dashboard page)
function refreshLogs() {
    if (window.dashboard) {
        window.dashboard.loadLogs();
    } else {
        console.warn('Dashboard not initialized');
    }
}

function loadNextLogs() {
    if (window.dashboard) {
        window.dashboard.loadNextLogs();
    }
}

function loadPreviousLogs() {
    if (window.dashboard) {
        window.dashboard.loadPreviousLogs();
    }
}

function scanPrompt() {
    if (window.dashboard) {
        window.dashboard.scanPrompt();
    }
}

function clearScanner() {
    if (window.dashboard) {
        window.dashboard.clearScanner();
    }
}

function clearLogs() {
    if (window.dashboard) {
        window.dashboard.clearLogs();
    }
}

// Export for potential module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AIPIFThemeManager, AIPIFDashboard };

}


