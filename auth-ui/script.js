// DOM Elements
const themeToggle = document.getElementById('themeToggle');
const toastContainer = document.getElementById('toastContainer');
const BASE_PATH = window.location.pathname.startsWith('/auth') ? '/auth' : '';
const withBase = (path) => `${BASE_PATH}${path}`;

// Initialize Particles.js
function initParticles() {
    if (typeof particlesJS !== 'undefined') {
        particlesJS('particles-js', {
            particles: {
                number: {
                    value: 80,
                    density: {
                        enable: true,
                        value_area: 800
                    }
                },
                color: {
                    value: "#ffffff"
                },
                shape: {
                    type: "circle"
                },
                opacity: {
                    value: 0.3,
                    random: true,
                    anim: {
                        enable: true,
                        speed: 1,
                        opacity_min: 0.1,
                        sync: false
                    }
                },
                size: {
                    value: 3,
                    random: true,
                    anim: {
                        enable: true,
                        speed: 2,
                        size_min: 0.1,
                        sync: false
                    }
                },
                line_linked: {
                    enable: true,
                    distance: 150,
                    color: "#ffffff",
                    opacity: 0.2,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 1,
                    direction: "none",
                    random: true,
                    straight: false,
                    out_mode: "out",
                    bounce: false,
                    attract: {
                        enable: false,
                        rotateX: 600,
                        rotateY: 1200
                    }
                }
            },
            interactivity: {
                detect_on: "canvas",
                events: {
                    onhover: {
                        enable: true,
                        mode: "repulse"
                    },
                    onclick: {
                        enable: true,
                        mode: "push"
                    },
                    resize: true
                }
            },
            retina_detect: true
        });
    }
}

// Theme Toggle
function initThemeToggle() {
    if (themeToggle) {
        // Check for saved theme or prefer-color-scheme
        const savedTheme = localStorage.getItem('theme') || 'dark';
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        
        // Set initial theme
        if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
            document.documentElement.setAttribute('data-theme', 'dark');
            themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            document.documentElement.setAttribute('data-theme', 'light');
            themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
        }
        
        // Toggle theme on click
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            
            if (newTheme === 'dark') {
                themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
                showToast('Dark mode enabled', 'success');
            } else {
                themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
                showToast('Light mode enabled', 'success');
            }
            
            // Update CSS variables for light theme
            updateThemeVariables(newTheme);
        });
    }
}

// Update CSS Variables for Theme
function updateThemeVariables(theme) {
    const root = document.documentElement;
    
    if (theme === 'light') {
        root.style.setProperty('--dark', '#f8f9fa');
        root.style.setProperty('--dark-light', '#e9ecef');
        root.style.setProperty('--light', '#1a1a2e');
        root.style.setProperty('--white', '#16213e');
        root.style.setProperty('--gray', '#495057');
        root.style.setProperty('--glass-bg', 'rgba(255, 255, 255, 0.7)');
        root.style.setProperty('--glass-border', 'rgba(0, 0, 0, 0.1)');
        root.style.setProperty('--glass-shadow', '0 8px 32px rgba(0, 0, 0, 0.1)');
    } else {
        root.style.setProperty('--dark', '#1a1a2e');
        root.style.setProperty('--dark-light', '#16213e');
        root.style.setProperty('--light', '#edf2f4');
        root.style.setProperty('--white', '#ffffff');
        root.style.setProperty('--gray', '#8d99ae');
        root.style.setProperty('--glass-bg', 'rgba(255, 255, 255, 0.1)');
        root.style.setProperty('--glass-border', 'rgba(255, 255, 255, 0.2)');
        root.style.setProperty('--glass-shadow', '0 8px 32px rgba(31, 38, 135, 0.37)');
    }
}

// Toast Notification System
function showToast(message, type = 'info', duration = 5000) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    // Icon based on type
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';
    if (type === 'warning') icon = 'exclamation-triangle';
    
    toast.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
        <button class="toast-close" style="margin-left: auto; background: none; border: none; color: inherit; cursor: pointer;">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    toastContainer.appendChild(toast);
    
    // Close button
    const closeBtn = toast.querySelector('.toast-close');
    closeBtn.addEventListener('click', () => {
        removeToast(toast);
    });
    
    // Auto remove after duration
    setTimeout(() => {
        if (toast.parentNode) {
            removeToast(toast);
        }
    }, duration);
    
    return toast;
}

function removeToast(toast) {
    toast.style.animation = 'slideInRight 0.3s ease-out reverse';
    setTimeout(() => {
        if (toast.parentNode) {
            toastContainer.removeChild(toast);
        }
    }, 300);
}

// Form Validation
class FormValidator {
    constructor(formId) {
        this.form = document.getElementById(formId);
        this.inputs = {};
        this.errors = {};
        this.init();
    }
    
    init() {
        if (!this.form) return;
        
        // Get all form inputs with data-validation attribute
        this.form.querySelectorAll('[data-validation]').forEach(input => {
            const name = input.id;
            this.inputs[name] = input;
            this.errors[name] = document.getElementById(`${name}Error`);
            
            // Add input event listeners
            input.addEventListener('input', () => this.validateField(name));
            input.addEventListener('blur', () => this.validateField(name));
        });
        
        // Form submit handler
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            if (this.validateAll()) {
                this.onSubmit();
            }
        });
    }
    
    validateField(fieldName) {
        const input = this.inputs[fieldName];
        const error = this.errors[fieldName];
        const value = input.value.trim();
        let isValid = true;
        let message = '';
        
        switch(fieldName) {
            case 'email':
            case 'resetEmail':
            case 'signupEmail':
                isValid = this.validateEmail(value);
                message = 'Please enter a valid email address';
                break;
                
            case 'password':
            case 'signupPassword':
                isValid = this.validatePassword(value);
                message = 'Password must be at least 8 characters';
                break;
                
            case 'confirmPassword':
                const password = this.inputs['signupPassword']?.value || '';
                isValid = value === password;
                message = 'Passwords do not match';
                break;
                
            case 'fullName':
                isValid = value.length >= 2;
                message = 'Name must be at least 2 characters';
                break;
        }
        
        this.showError(fieldName, !isValid, message);
        return isValid;
    }
    
    validateAll() {
        let isValid = true;
        Object.keys(this.inputs).forEach(field => {
            if (!this.validateField(field)) {
                isValid = false;
            }
        });
        return isValid;
    }
    
    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    
    validatePassword(password) {
        return password.length >= 8;
    }
    
    showError(fieldName, show, message) {
        const error = this.errors[fieldName];
        if (error) {
            error.textContent = message;
            if (show) {
                error.classList.add('show');
                this.inputs[fieldName].style.borderColor = 'var(--danger)';
            } else {
                error.classList.remove('show');
                this.inputs[fieldName].style.borderColor = '';
            }
        }
    }
    
    onSubmit() {
        // To be implemented in auth.js
        console.log('Form submitted successfully');
    }
}

// Password Strength Checker
class PasswordStrength {
    constructor(passwordInputId, strengthMeterId, strengthTextId) {
        this.passwordInput = document.getElementById(passwordInputId);
        this.strengthMeter = document.getElementById(strengthMeterId);
        this.strengthText = document.getElementById(strengthTextId);
        this.segments = [];
        
        if (this.passwordInput && this.strengthMeter) {
            this.init();
        }
    }
    
    init() {
        // Get strength segments
        for (let i = 1; i <= 4; i++) {
            this.segments.push(document.getElementById(`strength${i}`));
        }
        
        // Add input listener
        this.passwordInput.addEventListener('input', () => this.checkStrength());
    }
    
    checkStrength() {
        const password = this.passwordInput.value;
        let strength = 0;
        
        // Length check
        if (password.length >= 8) strength++;
        if (password.length >= 12) strength++;
        
        // Complexity checks
        if (/[A-Z]/.test(password)) strength++;
        if (/[a-z]/.test(password)) strength++;
        if (/[0-9]/.test(password)) strength++;
        if (/[^A-Za-z0-9]/.test(password)) strength++;
        
        // Cap at 4 for our segments
        strength = Math.min(strength, 4);
        
        // Update UI
        this.updateStrengthMeter(strength);
        this.updateStrengthText(strength);
    }
    
    updateStrengthMeter(strength) {
        this.segments.forEach((segment, index) => {
            segment.classList.remove('active', 'danger', 'warning');
            
            if (index < strength) {
                segment.classList.add('active');
                
                // Color coding
                if (strength <= 2) {
                    segment.classList.add('danger');
                } else if (strength === 3) {
                    segment.classList.add('warning');
                }
            }
        });
    }
    
    updateStrengthText(strength) {
        const texts = [
            'Very weak',
            'Weak',
            'Fair',
            'Good',
            'Strong'
        ];
        
        if (this.strengthText) {
            this.strengthText.textContent = texts[strength];
            this.strengthText.style.color = strength <= 2 ? 'var(--danger)' : 
                                          strength === 3 ? 'var(--warning)' : 
                                          'var(--success)';
        }
    }
}

// Password Toggle Visibility
function initPasswordToggles() {
    document.querySelectorAll('.password-toggle').forEach(toggle => {
        toggle.addEventListener('click', function() {
            const input = this.previousElementSibling;
            const icon = this.querySelector('i');
            
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.remove('fa-eye');
                icon.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                icon.classList.remove('fa-eye-slash');
                icon.classList.add('fa-eye');
            }
        });
    });
}

// Loading State Management
class LoadingManager {
    static show(button) {
        if (!button) return;
        
        button.classList.add('button-loading');
        button.disabled = true;
        
        // Store original text if not already loading
        if (!button.dataset.originalText) {
            button.dataset.originalText = button.textContent;
        }
    }
    
    static hide(button) {
        if (!button) return;
        
        button.classList.remove('button-loading');
        button.disabled = false;
        
        // Restore original text
        if (button.dataset.originalText) {
            button.textContent = button.dataset.originalText;
        }
    }
}

// Progress Bar Management
class ProgressManager {
    constructor(barId, totalSteps) {
        this.bar = document.getElementById(barId);
        this.totalSteps = totalSteps;
        this.currentStep = 0;
    }
    
    updateProgress(step) {
        if (!this.bar) return;
        
        this.currentStep = step;
        const percentage = (step / this.totalSteps) * 100;
        this.bar.style.width = `${percentage}%`;
    }
    
    reset() {
        this.currentStep = 0;
        if (this.bar) {
            this.bar.style.width = '0%';
        }
    }
}

// Initialize all components when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Initialize particles background
    initParticles();
    
    // Initialize theme toggle
    initThemeToggle();
    
    // Initialize password toggles
    initPasswordToggles();
    
    // Initialize form validators
    if (document.getElementById('loginForm')) {
        window.loginValidator = new FormValidator('loginForm');
    }
    
    if (document.getElementById('signupForm')) {
        window.signupValidator = new FormValidator('signupForm');
        
        // Initialize password strength checker
        window.passwordStrength = new PasswordStrength(
            'signupPassword',
            'strengthMeter',
            'strengthText'
        );
        
        // Initialize progress manager for signup
        window.signupProgress = new ProgressManager('signupProgress', 4);
        
        // Update progress on input
        document.getElementById('signupForm')?.addEventListener('input', () => {
            const inputs = document.querySelectorAll('#signupForm input');
            const filled = Array.from(inputs).filter(input => input.value.trim() !== '').length;
            window.signupProgress.updateProgress(filled);
        });
    }
    
    if (document.getElementById('resetForm')) {
        window.resetValidator = new FormValidator('resetForm');
    }
    
    // Initialize logout button
    const logoutButton = document.getElementById('logoutButton');
    if (logoutButton) {
        logoutButton.addEventListener('click', (e) => {
            e.preventDefault();
            if (!confirm('Are you sure you want to logout?')) {
                return;
            }
            if (window.authManager) {
                window.authManager.logout();
            } else {
                localStorage.removeItem('userData');
                sessionStorage.removeItem('userData');
                window.location.href = withBase('/login');
            }
        });
    }
    
    // Load user data for dashboard
    const userAvatar = document.getElementById('userAvatar');
    const userName = document.getElementById('userName');
    const userEmail = document.getElementById('userEmail');
    
    if (userAvatar && userName && userEmail) {
        const storedUser = localStorage.getItem('userData') || sessionStorage.getItem('userData');
        const userData = storedUser ? JSON.parse(storedUser) : {
            name: 'John Doe',
            email: 'john@example.com'
        };
        
        // Set initials for avatar
        const initials = userData.name
            .split(' ')
            .map(n => n[0])
            .join('')
            .toUpperCase();
        
        userAvatar.textContent = initials;
        userName.textContent = userData.name;
        userEmail.textContent = userData.email;
    }
    
    // Check authentication for protected pages
    const storedUser = localStorage.getItem('userData') || sessionStorage.getItem('userData');
    const dashboardPath = withBase('/dashboard');
    const isProtectedPage =
        window.location.pathname === dashboardPath ||
        window.location.pathname === `${dashboardPath}/`;

    if (isProtectedPage && !storedUser) {
        window.location.href = withBase('/login');
        showToast('Please login to access dashboard', 'warning');
    }

    // Verify server-side authentication before redirecting to dashboard
    if (!isProtectedPage && storedUser) {
        const authPages = [
            BASE_PATH,
            `${BASE_PATH}/`,
            withBase('/'),
            withBase('/login'),
            withBase('/register'),
            withBase('/forgot'),
            withBase('/index.html'),
            withBase('/signup.html'),
            withBase('/reset-password.html')
        ];

        if (authPages.includes(window.location.pathname)) {
            // Verify with server before redirecting to prevent redirect loop
            fetch(withBase('/api/me'))
                .then(response => response.json())
                .then(data => {
                    if (data.authenticated) {
                        window.location.href = withBase('/dashboard');
                    } else {
                        // Clear stale client-side data since server doesn't recognize user
                        localStorage.removeItem('userData');
                        sessionStorage.removeItem('userData');
                        console.log('Cleared stale authentication data');
                    }
                })
                .catch(error => {
                    console.error('Failed to verify authentication:', error);
                });
        }
    }
});
