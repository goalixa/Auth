const authBasePath = window.location.pathname.startsWith('/auth') ? '/auth' : '';
const resolveBasePath =
    window.withBase || ((path) => `${authBasePath}${path}`);
const resolveNextParam = () => {
    const params = new URLSearchParams(window.location.search);
    return params.get('next');
};

// Authentication API Configuration
const API_CONFIG = {
    baseURL: authBasePath,
    endpoints: {
        login: '/api/login',
        register: '/api/register',
        resetPassword: '/api/forgot',
        logout: '/api/logout',
        refresh: '/api/refresh'
    },
    headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    accessTokenTTL: 15 * 60 * 1000, // 15 minutes in milliseconds
    refreshThreshold: 14 * 60 * 1000 // Refresh at 14 minutes (1 minute before expiry)
};

// Authentication Manager
class AuthManager {
    constructor() {
        this.userKey = 'userData';
        this.tokenRefreshKey = 'tokenRefreshTimer';
        this.init();
    }

    init() {
        // Check for existing user data
        this.user = this.getStoredUser();
        // Setup token refresh if user is authenticated
        if (this.user) {
            this.setupTokenRefresh();
        }
    }

    getStoredUser() {
        const localUser = localStorage.getItem(this.userKey);
        if (localUser) {
            return JSON.parse(localUser);
        }
        const sessionUser = sessionStorage.getItem(this.userKey);
        if (sessionUser) {
            return JSON.parse(sessionUser);
        }
        return null;
    }
    
    // Login method
    async login(email, password, rememberMe = false) {
        const loginButton = document.getElementById('loginButton');
        try {
            // Show loading state
            if (loginButton) {
                loginButton.disabled = true;
                loginButton.innerHTML = '<div class="spinner"></div>';
            }
            
            const response = await fetch(
                `${API_CONFIG.baseURL}${API_CONFIG.endpoints.login}`,
                {
                    method: 'POST',
                    headers: API_CONFIG.headers,
                    body: JSON.stringify({ email, password })
                }
            );
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Invalid email or password');
            }

            const user = data.user || { email };
            this.setAuthData(user, rememberMe);

            // Show success message
            showToast('Login successful!', 'success');

            // Redirect to next URL or dashboard
            setTimeout(() => {
                const next = resolveNextParam();
                if (next && (next.startsWith('http://') || next.startsWith('https://'))) {
                    // External URL - redirect directly
                    window.location.href = next;
                } else if (next) {
                    // Internal path - use base path
                    window.location.href = resolveBasePath(next);
                } else {
                    // No next URL - go to dashboard
                    window.location.href = resolveBasePath('/dashboard');
                }
            }, 500);
            
            return { success: true, user };
            
        } catch (error) {
            showToast(error.message, 'error');
            return { success: false, error: error.message };
        } finally {
            // Reset button state
            if (loginButton) {
                loginButton.disabled = false;
                loginButton.innerHTML = '<span id="buttonText">Sign In</span>';
            }
        }
    }
    
    // Register method
    async register(userData) {
        const signupButton = document.getElementById('signupButton');
        try {
            if (signupButton) {
                signupButton.disabled = true;
                signupButton.innerHTML = '<div class="spinner"></div>';
            }
            
            const response = await fetch(
                `${API_CONFIG.baseURL}${API_CONFIG.endpoints.register}`,
                {
                    method: 'POST',
                    headers: API_CONFIG.headers,
                    body: JSON.stringify({
                        email: userData.email,
                        password: userData.password,
                        name: userData.name
                    })
                }
            );
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Registration failed');
            }

            const displayName = userData.name || userData.email.split('@')[0];
            const newUser = {
                email: data.user?.email || userData.email,
                name: displayName,
                avatar: displayName.split(' ').map(n => n[0]).join('').toUpperCase()
            };
            this.setAuthData(newUser, true);
            
            showToast('Registration successful!', 'success');
            
            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = resolveBasePath('/dashboard');
            }, 500);
            
            return { success: true, user: newUser };
            
        } catch (error) {
            showToast(error.message, 'error');
            return { success: false, error: error.message };
        } finally {
            if (signupButton) {
                signupButton.disabled = false;
                signupButton.innerHTML = '<span id="signupButtonText">Create Account</span>';
            }
        }
    }
    
    // Reset password method
    async resetPassword(email) {
        const resetButton = document.getElementById('resetButton');
        try {
            if (resetButton) {
                resetButton.disabled = true;
                resetButton.innerHTML = '<div class="spinner"></div>';
            }
            
            const response = await fetch(
                `${API_CONFIG.baseURL}${API_CONFIG.endpoints.resetPassword}`,
                {
                    method: 'POST',
                    headers: API_CONFIG.headers,
                    body: JSON.stringify({ email })
                }
            );
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to send reset email');
            }

            showToast(data.message || 'Reset instructions sent to your email', 'success');
            if (data.reset_link) {
                console.info('Reset link:', data.reset_link);
            }
            
            // Redirect to login after delay
            setTimeout(() => {
                window.location.href = resolveBasePath('/login');
            }, 3000);
            
            return { success: true };
            
        } catch (error) {
            showToast(error.message, 'error');
            return { success: false, error: error.message };
        } finally {
            if (resetButton) {
                resetButton.disabled = false;
                resetButton.innerHTML = '<span id="resetButtonText">Send Reset Link</span>';
            }
        }
    }
    
    // Logout method
    async logout() {
        localStorage.removeItem(this.userKey);
        sessionStorage.removeItem(this.userKey);
        this.user = null;

        await fetch(`${API_CONFIG.baseURL}${API_CONFIG.endpoints.logout}`, {
            method: 'POST',
            headers: API_CONFIG.headers
        }).catch(() => {});
        
        showToast('Logged out successfully', 'success');
        window.location.href = resolveBasePath('/login');
    }
    
    // Check if user is authenticated
    isAuthenticated() {
        return !!this.user;
    }
    
    // Get current user
    getCurrentUser() {
        return this.user;
    }
    
    // Helper methods
    setAuthData(user, rememberMe = false) {
        this.user = user;
        
        if (rememberMe) {
            localStorage.setItem(this.userKey, JSON.stringify(user));
            sessionStorage.removeItem(this.userKey);
        } else {
            sessionStorage.setItem(this.userKey, JSON.stringify(user));
            localStorage.removeItem(this.userKey);
        }
    }
    
    clearAuthData() {
        this.user = null;
        localStorage.removeItem(this.userKey);
        sessionStorage.removeItem(this.userKey);
        this.clearTokenRefresh();
    }

    // Token refresh methods
    async refreshAccessToken() {
        try {
            const response = await fetch(
                `${API_CONFIG.baseURL}${API_CONFIG.endpoints.refresh}`,
                {
                    method: 'POST',
                    headers: API_CONFIG.headers,
                    credentials: 'include' // Include cookies
                }
            );
            const data = await response.json().catch(() => ({}));
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to refresh token');
            }
            // Reset the refresh timer after successful refresh
            this.setupTokenRefresh();
            return { success: true, access_token: data.access_token };
        } catch (error) {
            console.error('Token refresh failed:', error);
            // If refresh fails, user needs to re-login
            this.clearAuthData();
            return { success: false, error: error.message };
        }
    }

    setupTokenRefresh() {
        // Clear any existing timer
        this.clearTokenRefresh();

        // Set up timer to refresh token before expiry
        const refreshDelay = API_CONFIG.accessTokenTTL - (60 * 1000); // Refresh 1 minute before expiry

        const timerId = setTimeout(async () => {
            const result = await this.refreshAccessToken();
            if (!result.success) {
                // Redirect to login if refresh failed
                showToast('Session expired. Please login again.', 'error');
                setTimeout(() => {
                    window.location.href = resolveBasePath('/login');
                }, 2000);
            }
        }, refreshDelay);

        // Store timer ID for cleanup
        localStorage.setItem(this.tokenRefreshKey, timerId.toString());
    }

    clearTokenRefresh() {
        const timerId = localStorage.getItem(this.tokenRefreshKey);
        if (timerId) {
            clearTimeout(parseInt(timerId, 10));
            localStorage.removeItem(this.tokenRefreshKey);
        }
    }

    // Social login methods
    async socialLogin(provider) {
        try {
            if (provider.toLowerCase() === 'google') {
                const next = resolveNextParam();
                const baseUrl = resolveBasePath('/login/google');
                const redirectUrl = next ? `${baseUrl}?next=${encodeURIComponent(next)}` : baseUrl;
                window.location.href = redirectUrl;
                return;
            }
            showToast(`${provider} login is not configured yet.`, 'warning');
        } catch (error) {
            showToast(`Failed to login with ${provider}`, 'error');
        }
    }
}

// Initialize Auth Manager
const authManager = new AuthManager();

// Fetch interceptor for auto-refresh on 401
const originalFetch = window.fetch;
window.fetch = async function(...args) {
    const response = await originalFetch(...args);

    // If response is 401 Unauthorized, try to refresh token
    if (response.status === 401 && authManager.isAuthenticated()) {
        const refreshResult = await authManager.refreshAccessToken();

        // If refresh successful, retry the original request
        if (refreshResult.success) {
            // Retry the original request with updated cookies
            return originalFetch(...args);
        }
    }

    return response;
};

// Form Submission Handlers
document.addEventListener('DOMContentLoaded', () => {
    // Login form submission
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const rememberMe = document.getElementById('rememberMe')?.checked || false;
            
            // Validate inputs
            if (!email || !password) {
                showToast('Please fill in all fields', 'error');
                return;
            }
            
            await authManager.login(email, password, rememberMe);
        });
    }
    
    // Signup form submission
    const signupForm = document.getElementById('signupForm');
    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const name = document.getElementById('fullName').value;
            const email = document.getElementById('signupEmail').value;
            const password = document.getElementById('signupPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const terms = document.getElementById('terms').checked;
            
            // Validation
            if (!name || !email || !password || !confirmPassword) {
                showToast('Please fill in all fields', 'error');
                return;
            }
            
            if (!terms) {
                showToast('You must agree to the terms and conditions', 'error');
                return;
            }
            
            if (password !== confirmPassword) {
                showToast('Passwords do not match', 'error');
                return;
            }
            
            if (password.length < 8) {
                showToast('Password must be at least 8 characters', 'error');
                return;
            }
            
            const userData = {
                name,
                email,
                password,
                confirmPassword
            };
            
            await authManager.register(userData);
        });
    }
    
    // Reset password form submission
    const resetForm = document.getElementById('resetForm');
    if (resetForm) {
        resetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('resetEmail').value;
            
            if (!email) {
                showToast('Please enter your email address', 'error');
                return;
            }
            
            await authManager.resetPassword(email);
        });
    }
    
    // Social login buttons
    document.querySelectorAll('.social-button').forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            const provider = button.classList.contains('google') ? 'Google' :
                           button.classList.contains('github') ? 'GitHub' : 'Twitter';
            
            await authManager.socialLogin(provider);
        });
    });
    
});

// Export auth manager for global use
window.authManager = authManager;
