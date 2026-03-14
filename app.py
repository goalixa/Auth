import base64
import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from time import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from dotenv import load_dotenv
from flask import (
    Flask,
    g,
    make_response,
    redirect,
    request,
    url_for,
)
from sqlalchemy.exc import IntegrityError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, Summary, Info, generate_latest

from auth.jwt import (
    create_access_token,
    create_refresh_token_jwt,
    create_refresh_token_string,
    decode_access_token,
    decode_refresh_token,
)
from auth.models import (
    EmailVerificationToken,
    PasswordResetToken,
    RefreshToken,
    User,
    cleanup_expired_tokens,
    create_email_verification_token,
    create_reset_token,
    get_user_active_tokens,
    init_db,
    revoke_all_user_tokens,
)
from auth.oauth import init_oauth, oauth
from auth.email_service import email_service

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data.db")
SECRETS_DIR = "/run/secrets"


# ============= Input Validation and Sanitization =============
def sanitize_email(email: str) -> str:
    """
    Validate and sanitize email address.

    Args:
        email: Raw email input

    Returns:
        Sanitized email address or empty string if invalid

    Security:
        - Removes control characters
        - Validates email format
        - Converts to lowercase
        - Strips whitespace
    """
    if not email:
        return ""

    # Remove control characters and null bytes
    email = re.sub(r'[\x00-\x1f\x7f]', '', email)

    # Strip whitespace and convert to lowercase
    email = email.strip().lower()

    # Basic email format validation
    # RFC 5322 compliant (simplified)
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return ""

    # Additional check for consecutive dots which can be problematic
    if '..' in email:
        return ""

    return email


def sanitize_password(password: str) -> str:
    """
    Sanitize password input.

    Args:
        password: Raw password input

    Returns:
        Sanitized password string

    Security:
        - Removes null bytes
        - Preserves special characters (needed for passwords)
        - Trims to reasonable max length (prevents DoS)
    """
    if not password:
        return ""

    # Remove null bytes but keep other characters
    # (passwords can contain special characters)
    password = password.replace('\x00', '')

    # Limit password length to prevent DoS
    # Max 128 characters is reasonable for passwords
    if len(password) > 128:
        password = password[:128]

    return password


def validate_email(email: str) -> tuple[bool, str]:
    """
    Validate email address with detailed error messages.

    Args:
        email: Email to validate

    Returns:
        (is_valid, error_message)
    """
    if not email:
        return False, "Email is required."

    sanitized = sanitize_email(email)
    if not sanitized:
        return False, "Invalid email format."

    return True, sanitized


def sanitize_string_input(input_str: str, max_length: int = 255) -> str:
    """
    Generic string sanitization for user input.

    Args:
        input_str: Raw input string
        max_length: Maximum allowed length

    Returns:
        Sanitized string
    """
    if not input_str:
        return ""

    # Remove control characters and null bytes
    sanitized = re.sub(r'[\x00-\x1f\x7f]', '', str(input_str))

    # Trim to max length
    sanitized = sanitized[:max_length].strip()

    return sanitized



def read_docker_secret(name):
    secret_path = os.path.join(SECRETS_DIR, name)
    try:
        with open(secret_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except FileNotFoundError:
        return None


def get_config_value(env_key, default=None):
    value = os.getenv(env_key)
    if value:
        return value
    secret_value = read_docker_secret(env_key)
    if secret_value:
        return secret_value
    return default


def get_jwt_secret():
    """
    Resolve the JWT signing secret. Preference order:
    1) AUTH_JWT_SECRET (env or /run/secrets)
    2) AUTH_SECRET_KEY (env or /run/secrets) for backward compatibility

    Raises:
        ValueError: If no JWT secret is configured
    """
    secret = get_config_value("AUTH_JWT_SECRET") or get_config_value("AUTH_SECRET_KEY")
    if not secret:
        raise ValueError(
            "JWT_SECRET not configured. Please set AUTH_JWT_SECRET or AUTH_SECRET_KEY "
            "environment variable or provide it via /run/secrets."
        )
    return secret


def normalize_origin(value):
    """Normalize a URL/origin to scheme://netloc for allow-list checks."""
    candidate = (value or "").strip()
    if not candidate:
        return None
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def parse_allowed_origins(raw_allowlist, default_return_to):
    allowed = set()
    for item in (raw_allowlist or "").split(","):
        origin = normalize_origin(item)
        if origin:
            allowed.add(origin)
    default_origin = normalize_origin(default_return_to)
    if default_origin:
        allowed.add(default_origin)
    return sorted(allowed)


def encode_oauth_state(payload):
    """
    Encode OAuth state with HMAC signature to prevent tampering.

    Format: base64(payload).base64(signature)
    This prevents attackers from modifying the return_to URL.
    """
    # Get JWT secret for signing
    secret = get_jwt_secret()

    # Serialize payload
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # Create signature
    signature = hmac.new(
        secret.encode("utf-8"),
        raw,
        hashlib.sha256
    ).digest()

    # Encode both payload and signature
    encoded_payload = base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")
    encoded_signature = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    # Return combined state
    return f"{encoded_payload}.{encoded_signature}"


def decode_oauth_state(state):
    """
    Decode and validate OAuth state with HMAC signature verification.

    Returns empty dict if signature is invalid or state is malformed.
    """
    if not state:
        app.logger.warning("OAuth state is empty")
        return {}

    try:
        # Split payload and signature
        parts = state.split(".")
        if len(parts) != 2:
            app.logger.warning("OAuth state has invalid format")
            return {}

        encoded_payload = parts[0]
        encoded_signature = parts[1]

        # Decode payload
        padding = "=" * (-len(encoded_payload) % 4)
        decoded = base64.urlsafe_b64decode(f"{encoded_payload}{padding}".encode("utf-8"))
        payload_bytes = decoded

        # Verify signature
        secret = get_jwt_secret()
        expected_signature = hmac.new(
            secret.encode("utf-8"),
            payload_bytes,
            hashlib.sha256
        ).digest()

        # Decode provided signature
        sig_padding = "=" * (-len(encoded_signature) % 4)
        provided_signature = base64.urlsafe_b64decode(
            f"{encoded_signature}{sig_padding}".encode("utf-8")
        )

        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(provided_signature, expected_signature):
            app.logger.warning("OAuth state signature verification failed")
            return {}

        # Parse payload
        payload = json.loads(payload_bytes.decode("utf-8"))
        if isinstance(payload, dict):
            return payload

    except (ValueError, TypeError) as e:
        app.logger.warning(f"Failed to decode OAuth state: {e}")
        return {}
    except Exception as e:
        app.logger.error(f"Unexpected error decoding OAuth state: {e}")
        return {}

    return {}


def append_query_params(url, extra_params):
    """Append query parameters to a URL while preserving existing params."""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in extra_params.items():
        if value is not None:
            query[key] = str(value)
    return urlunparse(parsed._replace(query=urlencode(query)))

# ============= HTTP Request Metrics =============
REQUEST_COUNT = Counter(
    "goalixa_auth_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "http_status"],
)
REQUEST_LATENCY = Histogram(
    "goalixa_auth_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
)
REQUEST_SIZE_BYTES = Summary(
    "goalixa_auth_http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "endpoint"]
)
RESPONSE_SIZE_BYTES = Summary(
    "goalixa_auth_http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "endpoint", "http_status"]
)
INPROGRESS_REQUESTS = Gauge(
    "goalixa_auth_http_requests_inprogress",
    "In progress HTTP requests",
)

# ============= Authentication Metrics =============
AUTH_LOGIN_TOTAL = Counter(
    "goalixa_auth_login_total",
    "Total login attempts",
    ["status"],  # status: success, failed_credentials, failed_inactive, missing_creds
)
AUTH_REGISTER_TOTAL = Counter(
    "goalixa_auth_register_total",
    "Total registration attempts",
    ["status"],  # status: success, failed_disabled, failed_exists, failed_validation
)
AUTH_LOGOUT_TOTAL = Counter(
    "goalixa_auth_logout_total",
    "Total logout attempts",
    ["status"],
)
AUTH_REFRESH_TOTAL = Counter(
    "goalixa_auth_token_refresh_total",
    "Total token refresh attempts",
    ["status"],  # status: success, failed_missing, failed_invalid, failed_expired, failed_user_inactive
)
AUTH_TOKEN_ISSUED_TOTAL = Counter(
    "goalixa_auth_token_issued_total",
    "Total tokens issued",
    ["token_type"],  # token_type: access, refresh
)
AUTH_VALIDATION_TOTAL = Counter(
    "goalixa_auth_validation_total",
    "Total token validations",
    ["token_type", "status"],  # token_type: access, refresh; status: success, failed, expired
)

# ============= OAuth Metrics =============
OAUTH_GOOGLE_TOTAL = Counter(
    "goalixa_auth_oauth_google_total",
    "Total Google OAuth operations",
    ["operation", "status"],  # operation: start, callback, user_created, user_login
)
OAUTH_GOOGLE_DURATION_SECONDS = Histogram(
    "goalixa_auth_oauth_google_duration_seconds",
    "Google OAuth operation duration",
    ["operation"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# ============= Password Reset Metrics =============
PASSWORD_RESET_REQUEST_TOTAL = Counter(
    "goalixa_auth_password_reset_request_total",
    "Total password reset requests",
    ["status"],  # status: success, failed_validation
)
PASSWORD_RESET_CONFIRM_TOTAL = Counter(
    "goalixa_auth_password_reset_confirm_total",
    "Total password reset confirmations",
    ["status"],  # status: success, failed_invalid, failed_expired
)

# ============= Database Metrics =============
DB_QUERY_DURATION_SECONDS = Histogram(
    "goalixa_auth_db_query_duration_seconds",
    "Database query duration",
    ["operation", "table"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5),
)
DB_QUERY_TOTAL = Counter(
    "goalixa_auth_db_queries_total",
    "Total database queries",
    ["operation", "table", "status"],
)
DB_CONNECTION_POOL = Gauge(
    "goalixa_auth_db_connection_pool",
    "Database connection pool size",
)

# ============= Session Metrics =============
ACTIVE_SESSIONS = Gauge(
    "goalixa_auth_active_sessions",
    "Number of active user sessions",
)
SESSION_DURATION_SECONDS = Histogram(
    "goalixa_auth_session_duration_seconds",
    "User session duration",
    buckets=(60, 300, 600, 1800, 3600, 7200, 14400, 28800, 43200, 86400),
)

# ============= Security Metrics =============
AUTH_FAILURES_TOTAL = Counter(
    "goalixa_auth_failures_total",
    "Total authentication failures",
    ["failure_type"],  # failure_type: invalid_credentials, invalid_token, expired_token, account_inactive
)
SUSPICIOUS_ACTIVITY_TOTAL = Counter(
    "goalixa_auth_suspicious_activity_total",
    "Total suspicious activity detected",
    ["activity_type"],  # activity_type: brute_force, token_abuse, abnormal_usage
)

# ============= Application Info =============
APP_INFO = Info(
    "goalixa_auth_app_info",
    "Goalixa Auth service information"
)


# ============= Rate Limiting =============
class RateLimiter:
    """
    Simple in-memory rate limiter for IP-based and action-based rate limiting.

    Tracks request counts per IP/action with configurable windows and limits.
    For production, consider using Redis for distributed rate limiting.
    """

    def __init__(self):
        # Structure: {key: [(timestamp, count), ...]}
        self._requests = {}
        # Track blocked IPs: {ip: until_timestamp}
        self._blocked = {}

    def _get_key(self, identifier, action):
        """Generate rate limit key."""
        return f"{identifier}:{action}"

    def _clean_old_entries(self, key, window_seconds):
        """Remove entries older than the window."""
        if key in self._requests:
            cutoff = time() - window_seconds
            self._requests[key] = [
                (ts, count) for ts, count in self._requests[key]
                if ts > cutoff
            ]
            # Remove empty lists
            if not self._requests[key]:
                del self._requests[key]

    def is_blocked(self, identifier):
        """Check if an identifier is temporarily blocked."""
        blocked_until = self._blocked.get(identifier)
        if blocked_until and time() < blocked_until:
            return True, int(blocked_until - time())
        # Clean up expired blocks
        if blocked_until:
            del self._blocked[identifier]
        return False, 0

    def is_rate_limited(
        self,
        identifier,
        action,
        limit,
        window_seconds=60,
        block_duration_seconds=300
    ):
        """
        Check if action should be rate limited.

        Args:
            identifier: Unique identifier (IP address, user_id, etc.)
            action: Action being performed (e.g., "login_attempt", "password_reset")
            limit: Max requests allowed in window
            window_seconds: Time window in seconds
            block_duration_seconds: How long to block if limit exceeded

        Returns:
            (is_limited, retry_after_seconds)
        """
        # Check if blocked
        blocked, retry_after = self.is_blocked(identifier)
        if blocked:
            return True, retry_after

        key = self._get_key(identifier, action)
        self._clean_old_entries(key, window_seconds)

        # Get current window count
        if key not in self._requests:
            self._requests[key] = []

        # Count requests in current window
        current_count = sum(count for _, count in self._requests[key])

        if current_count >= limit:
            # Block this identifier
            self._blocked[identifier] = time() + block_duration_seconds
            app.logger.warning(
                f"Rate limit exceeded for {action}",
                extra={"identifier": identifier, "count": current_count}
            )
            return True, block_duration_seconds

        # Add this request
        self._requests[key].append((time(), 1))
        return False, 0

    def reset(self, identifier=None, action=None):
        """Reset rate limit counters."""
        if identifier and action:
            key = self._get_key(identifier, action)
            if key in self._requests:
                del self._requests[key]
        elif identifier:
            # Clear all actions for this identifier
            for key in list(self._requests.keys()):
                if key.startswith(f"{identifier}:"):
                    del self._requests[key]


# Global rate limiter instance
rate_limiter = RateLimiter()


def get_client_ip():
    """Get client IP address from request."""
    # Check for forwarded headers (proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return request.remote_addr


def rate_limit(action, limit, window_seconds=60, block_duration_seconds=300):
    """
    Decorator for rate limiting endpoints.

    Args:
        action: Action name for rate limiting
        limit: Max requests allowed in window
        window_seconds: Time window (default 60s)
        block_duration_seconds: Block duration after limit exceeded (default 300s)
    """
    def decorator(f):
        def wrapped(*args, **kwargs):
            ip = get_client_ip()

            # Check rate limit
            is_limited, retry_after = rate_limiter.is_rate_limited(
                identifier=ip,
                action=action,
                limit=limit,
                window_seconds=window_seconds,
                block_duration_seconds=block_duration_seconds
            )

            if is_limited:
                app.logger.warning(
                    f"Rate limit applied for {action}",
                    extra={"ip": ip, "retry_after": retry_after}
                )
                response = {
                    "success": False,
                    "error": f"Too many attempts. Please try again in {retry_after} seconds."
                }, 429
                # Add Retry-After header
                if hasattr(response, 'headers'):
                    response.headers["Retry-After"] = str(retry_after)
                return response

            return f(*args, **kwargs)

        # Preserve function metadata
        wrapped.__name__ = f.__name__
        wrapped.__doc__ = f.__doc__
        return wrapped

    return decorator



# ============= Password Validation =============
def validate_password_complexity(password: str) -> tuple[bool, str]:
    """
    Validate password complexity requirements.

    Requirements:
    - Minimum 8 characters
    - At least one lowercase letter
    - At least one uppercase letter
    - At least one digit
    - At least one special character

    Returns:
        tuple: (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."

    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."

    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."

    return True, ""



def create_app():
    load_dotenv()
    app = Flask(__name__)
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    app.logger.setLevel(log_level)

    # Initialize application info
    APP_INFO.info({
        'version': os.getenv('APP_VERSION', '1.0.0'),
        'environment': os.getenv('ENVIRONMENT', 'development'),
        'service': 'goalixa-auth'
    })

    app.config["SECRET_KEY"] = get_config_value("AUTH_SECRET_KEY", "dev-auth-secret")
    app.config["SQLALCHEMY_DATABASE_URI"] = get_config_value(
        "AUTH_DATABASE_URI", f"sqlite:///{DB_PATH}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["AUTH_JWT_SECRET"] = get_jwt_secret()
    # Dual-token authentication configuration
    app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"] = int(
        get_config_value("AUTH_ACCESS_TOKEN_TTL_MINUTES", "15")
    )
    app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"] = int(
        get_config_value("AUTH_REFRESH_TOKEN_TTL_DAYS", "7")
    )
    app.config["AUTH_ACCESS_COOKIE_NAME"] = os.getenv(
        "AUTH_ACCESS_COOKIE_NAME", "goalixa_access"
    )
    app.config["AUTH_REFRESH_COOKIE_NAME"] = os.getenv(
        "AUTH_REFRESH_COOKIE_NAME", "goalixa_refresh"
    )
    # Use Lax for SameSite for better browser compatibility
    # Can be overridden to "None" for cross-site cookie scenarios
    samesite_config = get_config_value("AUTH_COOKIE_SAMESITE", "Lax")
    # Convert string "None" to Python None for Flask's set_cookie()
    # Flask needs None (not "None") to set SameSite=None correctly
    app.config["AUTH_COOKIE_SAMESITE"] = None if samesite_config == "None" else samesite_config
    app.config["AUTH_COOKIE_DOMAIN"] = get_config_value("AUTH_COOKIE_DOMAIN")
    # Default to True for secure cookies in production
    secure = get_config_value("AUTH_COOKIE_SECURE", "1") == "1"
    # When SameSite=None is used, Secure must be True for modern browsers
    if app.config["AUTH_COOKIE_SAMESITE"] is None:
        secure = True
    app.config["AUTH_COOKIE_SECURE"] = secure
    app.config["REGISTERABLE"] = os.getenv("REGISTERABLE", "1") == "1"
    app.config["GOOGLE_CLIENT_ID"] = get_config_value("GOOGLE_CLIENT_ID")
    app.config["GOOGLE_CLIENT_SECRET"] = get_config_value("GOOGLE_CLIENT_SECRET")
    app.config["GOOGLE_REDIRECT_URI"] = get_config_value("GOOGLE_REDIRECT_URI")
    app.config["AUTH_OAUTH_RETURN_TO_DEFAULT"] = (
        get_config_value("AUTH_OAUTH_RETURN_TO_DEFAULT")
        or get_config_value("GOALIXA_APP_URL")
    )
    app.config["AUTH_OAUTH_RETURN_TO_ALLOWED_ORIGINS"] = parse_allowed_origins(
        get_config_value("AUTH_OAUTH_RETURN_TO_ALLOWLIST", ""),
        app.config["AUTH_OAUTH_RETURN_TO_DEFAULT"],
    )
    # Authlib stores OAuth state in Flask session for callback validation.
    app.config["SESSION_COOKIE_SECURE"] = app.config["AUTH_COOKIE_SECURE"]
    app.config["SESSION_COOKIE_SAMESITE"] = app.config["AUTH_COOKIE_SAMESITE"]
    app.config["SESSION_COOKIE_DOMAIN"] = app.config["AUTH_COOKIE_DOMAIN"]

    app.logger.info(
        "app configured",
        extra={
            "registerable": app.config["REGISTERABLE"],
            "cookie_secure": app.config["AUTH_COOKIE_SECURE"],
            "google_oauth_enabled": bool(
                app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"]
            ),
        },
    )

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    init_db(app)
    init_oauth(app)

    def _clear_auth_cookie(response):
        """Remove auth cookies for both configured domain and host-only to avoid sticky invalid cookies."""
        cookie_names = [
            app.config["AUTH_ACCESS_COOKIE_NAME"],
            app.config["AUTH_REFRESH_COOKIE_NAME"],
        ]
        domains = [app.config["AUTH_COOKIE_DOMAIN"]]
        if app.config["AUTH_COOKIE_DOMAIN"] is not None:
            domains.append(None)  # also clear host-only variant
        for cookie_name in cookie_names:
            for domain in domains:
                response.set_cookie(
                    cookie_name,
                    "",
                    max_age=0,
                    httponly=True,
                    secure=app.config["AUTH_COOKIE_SECURE"],
                    samesite=app.config["AUTH_COOKIE_SAMESITE"],
                    path="/",
                    domain=domain,
                )
        return response

    @app.before_request
    def load_user():
        access_cookie_name = app.config["AUTH_ACCESS_COOKIE_NAME"]
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        access_token = request.cookies.get(access_cookie_name)
        refresh_token = request.cookies.get(refresh_cookie_name)
        g.current_user = None
        g.clear_auth_cookie = False

        # Public endpoints that don't require authentication
        public_endpoints = {
            "root",
            "health",
            "metrics",
            "static",
            "api_login",
            "api_register",
            "api_forgot_password",
            "api_password_reset_request",
            "api_password_reset_confirm",
            "api_logout",
            "api_refresh",
            "api_google_oauth_start",
            "api_google_oauth_callback",
            "admin_cleanup_tokens",
        }

        # Skip auth check for public endpoints
        if request.endpoint in public_endpoints:
            return

        # Try to authenticate with access token first
        if access_token:
            payload, err = decode_access_token(
                access_token, app.config["AUTH_JWT_SECRET"]
            )
            if not err and payload and "sub" in payload:
                try:
                    user_id = int(payload.get("sub"))
                except (TypeError, ValueError):
                    app.logger.warning(
                        "jwt sub is not a valid integer",
                        extra={"sub": payload.get("sub"), "path": request.path},
                    )
                else:
                    g.current_user = User.query.get(user_id)
                    if g.current_user:
                        app.logger.info(
                            "auth user loaded via access token",
                            extra={"user_id": g.current_user.id, "path": request.path},
                        )
                        return

        # Access token is missing or invalid, try refresh token
        if refresh_token:
            payload, err = decode_refresh_token(
                refresh_token, app.config["AUTH_JWT_SECRET"]
            )
            if not err and payload and "sub" in payload and "jti" in payload:
                from auth.models import db

                try:
                    user_id = int(payload.get("sub"))
                except (TypeError, ValueError):
                    app.logger.warning(
                        "refresh token sub is not a valid integer",
                        extra={"sub": payload.get("sub"), "path": request.path},
                    )
                else:
                    # Check database for token validity
                    refresh_token_record = RefreshToken.query.filter_by(
                        token_id=payload["jti"], user_id=user_id
                    ).first()

                    if refresh_token_record and refresh_token_record.is_valid():
                        user = User.query.get(user_id)
                        if user and user.active:
                            # Update last_seen_at timestamp
                            refresh_token_record.last_seen_at = datetime.now(timezone.utc)

                            # Auto-issue new access token
                            new_access_token = create_access_token(
                                user_id=user.id,
                                email=user.email,
                                secret=app.config["AUTH_JWT_SECRET"],
                                ttl_minutes=app.config[
                                    "AUTH_ACCESS_TOKEN_TTL_MINUTES"
                                ],
                            )

                            g.current_user = user
                            # Signal to set new access token cookie in after_request
                            g.new_access_token = new_access_token

                            # Commit the timestamp update
                            from auth.models import db
                            db.session.commit()

                            app.logger.info(
                                "auth user loaded via refresh token, access token refreshed",
                                extra={"user_id": user.id, "path": request.path},
                            )
                            return

        # No valid tokens found
        app.logger.info(
            "auth cookie missing or invalid",
            extra={
                "access_cookie_name": access_cookie_name,
                "refresh_cookie_name": refresh_cookie_name,
                "path": request.path,
            },
        )
        g.clear_auth_cookie = True
        if request.endpoint and request.endpoint.startswith("api_"):
            return
        return

    def _metrics_endpoint_label():
        if request.url_rule and request.url_rule.rule:
            return request.url_rule.rule
        return request.path or "unknown"

    @app.before_request
    def start_metrics_timer():
        g.metrics_skip = request.path == "/metrics"
        if g.metrics_skip:
            return
        g.metrics_start = time()
        g.metrics_inprogress = True
        INPROGRESS_REQUESTS.inc()

    @app.after_request
    def record_metrics(response):
        if getattr(g, "metrics_skip", False):
            return response
        if getattr(g, "metrics_inprogress", False):
            INPROGRESS_REQUESTS.dec()
            g.metrics_inprogress = False
        endpoint = _metrics_endpoint_label()
        REQUEST_COUNT.labels(request.method, endpoint, str(response.status_code)).inc()
        if hasattr(g, "metrics_start"):
            REQUEST_LATENCY.labels(request.method, endpoint).observe(
                time() - g.metrics_start
            )
        return response

    @app.teardown_request
    def finalize_metrics(error=None):
        if getattr(g, "metrics_inprogress", False):
            INPROGRESS_REQUESTS.dec()
            g.metrics_inprogress = False
        if error:
            app.logger.exception("request failed", extra={"path": request.path})

    @app.after_request
    def log_request(response):
        duration_ms = None
        if hasattr(g, "metrics_start"):
            duration_ms = int((time() - g.metrics_start) * 1000)
        if getattr(g, "clear_auth_cookie", False):
            response = _clear_auth_cookie(response)
        # Set new access token cookie if it was auto-refreshed
        if hasattr(g, "new_access_token"):
            response.set_cookie(
                app.config["AUTH_ACCESS_COOKIE_NAME"],
                g.new_access_token,
                max_age=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"] * 60,
                httponly=True,
                samesite=app.config["AUTH_COOKIE_SAMESITE"],
                secure=app.config["AUTH_COOKIE_SECURE"],
                path="/",
                domain=app.config["AUTH_COOKIE_DOMAIN"],
            )
        app.logger.info(
            "request complete",
            extra={
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "remote_addr": request.headers.get(
                    "X-Forwarded-For", request.remote_addr
                ),
            },
        )
        return response

    def get_device_info(request):
        """Extract device information from request."""
        user_agent = request.headers.get("User-Agent", "")

        # Detect device type from user agent
        device_type = "desktop"
        if any(mobile in user_agent.lower() for mobile in ["mobile", "android", "iphone"]):
            device_type = "mobile"
        elif any(tablet in user_agent.lower() for tablet in ["ipad", "tablet"]):
            device_type = "tablet"

        # Generate device name from user agent
        import re

        # Try to extract browser/device name
        if "Chrome" in user_agent:
            browser = "Chrome"
        elif "Firefox" in user_agent:
            browser = "Firefox"
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            browser = "Safari"
        elif "Edg" in user_agent:
            browser = "Edge"
        else:
            browser = "Browser"

        # Detect OS
        if "Windows" in user_agent:
            os_name = "Windows"
        elif "Mac" in user_agent or "OS X" in user_agent:
            os_name = "macOS"
        elif "Linux" in user_agent:
            os_name = "Linux"
        elif "Android" in user_agent:
            os_name = "Android"
        elif "iOS" in user_agent or "iPhone" in user_agent or "iPad" in user_agent:
            os_name = "iOS"
        else:
            os_name = "Unknown OS"

        device_name = f"{browser} on {os_name}"

        # Generate device fingerprint (simple hash of user agent + IP)
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if client_ip:
            # Handle X-Forwarded-For which may contain multiple IPs
            client_ip = client_ip.split(",")[0].strip()

        device_fingerprint = hashlib.sha256(
            f"{user_agent}:{client_ip}".encode()
        ).hexdigest()[:32]

        return {
            "device_name": device_name,
            "device_type": device_type,
            "device_id": device_fingerprint,
            "user_agent": user_agent[:500],  # Limit length
            "ip_address": client_ip,
        }

    def create_auth_tokens(user, request=None):
        """Create access and refresh tokens with device tracking."""
        # Create access token
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"],
        )
        AUTH_TOKEN_ISSUED_TOTAL.labels(token_type="access").inc()

        # Create refresh token
        from auth.models import db, revoke_oldest_tokens

        refresh_token_str = create_refresh_token_string()
        refresh_token_jwt = create_refresh_token_jwt(
            user_id=user.id,
            token_id=refresh_token_str,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"],
        )

        # Get device info from request
        device_info = {}
        if request:
            device_info = get_device_info(request)

        # Enforce max tokens per user (revoke oldest if needed)
        max_tokens = int(get_config_value("AUTH_MAX_TOKENS_PER_USER", "5"))
        revoke_oldest_tokens(user.id, max_tokens=max_tokens)

        # Store refresh token in database with device info
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"]
        )
        refresh_token = RefreshToken(
            token=refresh_token_str,
            token_id=refresh_token_str,
            user_id=user.id,
            expires_at=refresh_expires,
            device_name=device_info.get("device_name"),
            device_type=device_info.get("device_type"),
            device_id=device_info.get("device_id"),
            user_agent=device_info.get("user_agent"),
            ip_address=device_info.get("ip_address"),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.session.add(refresh_token)
        db.session.commit()
        AUTH_TOKEN_ISSUED_TOTAL.labels(token_type="refresh").inc()

        app.logger.info(
            "created auth tokens with device info",
            extra={
                "user_id": user.id,
                "device_type": device_info.get("device_type"),
                "device_name": device_info.get("device_name"),
            },
        )

        return access_token, refresh_token_jwt

    def set_auth_cookies(response, access_token, refresh_token_jwt):
        access_max_age = app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"] * 60
        refresh_max_age = app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"] * 86400

        response.set_cookie(
            app.config["AUTH_ACCESS_COOKIE_NAME"],
            access_token,
            max_age=access_max_age,
            httponly=True,
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
            secure=app.config["AUTH_COOKIE_SECURE"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
        )
        response.set_cookie(
            app.config["AUTH_REFRESH_COOKIE_NAME"],
            refresh_token_jwt,
            max_age=refresh_max_age,
            httponly=True,
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
            secure=app.config["AUTH_COOKIE_SECURE"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
        )
        return response

    def issue_auth_json_response(user):
        access_token, refresh_token_jwt = create_auth_tokens(user, request)
        app.logger.info(
            "issued auth json response with dual tokens",
            extra={"user_id": user.id, "email": user.email},
        )
        response = make_response({"success": True, "user": {"email": user.email}})
        return set_auth_cookies(response, access_token, refresh_token_jwt)

    def issue_auth_redirect_response(user, return_to):
        access_token, refresh_token_jwt = create_auth_tokens(user, request)
        app.logger.info(
            "issued auth redirect response with dual tokens",
            extra={"user_id": user.id, "email": user.email, "return_to": return_to},
        )
        response = make_response(redirect(return_to))
        return set_auth_cookies(response, access_token, refresh_token_jwt)

    def is_allowed_return_to(return_to):
        if not return_to:
            return False
        parsed = urlparse(return_to)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False
        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        allowed = app.config.get("AUTH_OAUTH_RETURN_TO_ALLOWED_ORIGINS", [])
        return origin in set(allowed)

    def resolve_return_to(candidate):
        requested = (candidate or "").strip()
        if requested:
            if is_allowed_return_to(requested):
                return requested
            return None
        default_return_to = app.config.get("AUTH_OAUTH_RETURN_TO_DEFAULT")
        if default_return_to and is_allowed_return_to(default_return_to):
            return default_return_to
        return None

    @app.route("/health", methods=["GET"])
    def health():
        return {"status": "ok"}

    @app.route("/metrics", methods=["GET"])
    def metrics():
        return app.response_class(
            generate_latest(),
            mimetype=CONTENT_TYPE_LATEST,
        )

    @app.route("/", methods=["GET"])
    def root():
        return {"service": "goalixa-auth", "status": "ok"}

    @app.route("/api/oauth/google/start", methods=["GET"])
    def api_google_oauth_start():
        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            return {"success": False, "error": "Google OAuth is not configured."}, 503

        return_to = resolve_return_to(
            request.args.get("return_to") or request.args.get("next")
        )
        if not return_to:
            return {
                "success": False,
                "error": "Invalid or missing return_to URL.",
                "allowed_origins": app.config["AUTH_OAUTH_RETURN_TO_ALLOWED_ORIGINS"],
            }, 400

        state = encode_oauth_state({"return_to": return_to})
        redirect_uri = app.config.get("GOOGLE_REDIRECT_URI") or url_for(
            "api_google_oauth_callback", _external=True
        )
        app.logger.info(
            "google oauth start",
            extra={"return_to": return_to, "redirect_uri": redirect_uri},
        )
        return oauth.google.authorize_redirect(redirect_uri, state=state)

    @app.route("/api/oauth/google/callback", methods=["GET"])
    def api_google_oauth_callback():
        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            return {"success": False, "error": "Google OAuth is not configured."}, 503

        state_payload = decode_oauth_state(request.args.get("state"))
        return_to = resolve_return_to(state_payload.get("return_to"))
        if not return_to:
            return {
                "success": False,
                "error": "Invalid OAuth return_to state.",
            }, 400

        if request.args.get("error"):
            app.logger.warning(
                "google oauth callback error",
                extra={
                    "error": request.args.get("error"),
                    "error_description": request.args.get("error_description"),
                },
            )
            return redirect(
                append_query_params(
                    return_to,
                    {"auth_error": request.args.get("error", "google_oauth_error")},
                )
            )

        try:
            token = oauth.google.authorize_access_token()
        except Exception as exc:  # pragma: no cover - runtime/provider dependent
            app.logger.warning("google oauth token exchange failed", extra={"error": str(exc)})
            return redirect(
                append_query_params(return_to, {"auth_error": "google_token_exchange_failed"})
            )

        user_info = token.get("userinfo") if token else None
        if not user_info:
            try:
                user_info = oauth.google.get(
                    "https://www.googleapis.com/oauth2/v3/userinfo"
                ).json()
            except Exception as exc:  # pragma: no cover - runtime/provider dependent
                app.logger.warning("google oauth userinfo request failed", extra={"error": str(exc)})
                return redirect(
                    append_query_params(return_to, {"auth_error": "google_userinfo_failed"})
                )

        email = str((user_info or {}).get("email", "")).strip().lower()
        email_verified = bool((user_info or {}).get("email_verified", False))
        if not email or not email_verified:
            app.logger.warning(
                "google oauth invalid email payload",
                extra={"email": email, "email_verified": email_verified},
            )
            return redirect(
                append_query_params(return_to, {"auth_error": "google_email_not_verified"})
            )

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                password_hash=generate_password_hash(uuid.uuid4().hex),
            )
            from auth.models import db

            db.session.add(user)
            db.session.commit()
            app.logger.info("google oauth user created", extra={"user_id": user.id, "email": email})

        if not user.active:
            app.logger.warning("google oauth inactive user", extra={"user_id": user.id})
            return redirect(
                append_query_params(return_to, {"auth_error": "account_inactive"})
            )

        app.logger.info("google oauth success", extra={"user_id": user.id, "email": email})
        return issue_auth_redirect_response(user, return_to)

    @app.route("/api/login", methods=["POST"])
    @rate_limit(action="login_attempt", limit=5, window_seconds=300, block_duration_seconds=900)
    def api_login():
        data = request.get_json(silent=True) or {}
        raw_email = data.get("email", "")
        raw_password = data.get("password", "")

        # Sanitize inputs
        email = sanitize_email(raw_email)
        password = sanitize_password(raw_password)

        if not email or not password:
            app.logger.warning("api login missing credentials")
            AUTH_LOGIN_TOTAL.labels(status="missing_credentials").inc()
            return {"success": False, "error": "Email and password are required."}, 400

        # Fetch user (always executes, timing is consistent)
        user = User.query.filter_by(email=email).first()

        # Use a dummy password hash to prevent timing attacks
        # This ensures constant-time execution whether user exists or not
        dummy_hash = generate_password_hash("dummy_password_for_timing_attack_prevention")

        # Check password with constant-time comparison
        # Always perform password verification to prevent timing attacks
        password_valid = False
        if user:
            # Real user - verify their password
            password_valid = check_password_hash(user.password_hash, password)
        else:
            # Non-existent user - still perform a hash verification to prevent timing attacks
            # This hash comparison will always fail, but takes the same time
            check_password_hash(dummy_hash, password)

        if not password_valid or not user:
            # Use generic error message to prevent user enumeration
            app.logger.warning("api login invalid credentials", extra={"email": email})
            AUTH_LOGIN_TOTAL.labels(status="failed_credentials").inc()
            AUTH_FAILURES_TOTAL.labels(failure_type="invalid_credentials").inc()
            return {"success": False, "error": "Invalid email or password."}, 401

        if not user.active:
            app.logger.warning("api login inactive user", extra={"user_id": user.id})
            AUTH_LOGIN_TOTAL.labels(status="failed_inactive").inc()
            AUTH_FAILURES_TOTAL.labels(failure_type="account_inactive").inc()
            return {"success": False, "error": "Your account is inactive."}, 403

        AUTH_LOGIN_TOTAL.labels(status="success").inc()
        return issue_auth_json_response(user)

    @app.route("/api/register", methods=["POST"])
    def api_register():
        if not app.config["REGISTERABLE"]:
            app.logger.warning("api register disabled")
            AUTH_REGISTER_TOTAL.labels(status="failed_disabled").inc()
            return {"success": False, "error": "Registration is disabled."}, 403
        data = request.get_json(silent=True) or {}

        # Sanitize inputs
        email = sanitize_email(data.get("email", ""))
        password = sanitize_password(data.get("password", ""))

        if not email or not password:
            app.logger.warning("api register missing credentials")
            AUTH_REGISTER_TOTAL.labels(status="failed_validation").inc()
            return {"success": False, "error": "Email and password are required."}, 400

        # Validate password complexity
        is_valid, error_msg = validate_password_complexity(password)
        if not is_valid:
            app.logger.warning("api register weak password", extra={"email": email})
            AUTH_REGISTER_TOTAL.labels(status="failed_validation").inc()
            return {"success": False, "error": error_msg}, 400

        existing = User.query.filter_by(email=email).first()
        if existing:
            app.logger.warning("api register email exists", extra={"email": email})
            AUTH_REGISTER_TOTAL.labels(status="failed_exists").inc()
            return {"success": False, "error": "Email already registered."}, 409
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
        )
        from auth.models import db

        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            app.logger.warning("api register email exists (integrity)", extra={"email": email})
            AUTH_REGISTER_TOTAL.labels(status="failed_exists").inc()
            return {"success": False, "error": "Email already registered."}, 409

        # Create email verification token
        verification_token = create_email_verification_token(user)
        app.logger.info("api register success", extra={"user_id": user.id, "email": email})
        AUTH_REGISTER_TOTAL.labels(status="success").inc()

        # Return auth response along with verification token
        response = issue_auth_json_response(user)
        response["verification_token"] = verification_token.token
        response["email_verified"] = user.email_verified
        response["message"] = "Registration successful. Please verify your email address."
        return response

    @app.route("/api/forgot", methods=["POST"])
    @rate_limit(action="password_reset_request", limit=3, window_seconds=300, block_duration_seconds=900)
    def api_forgot_password():
        data = request.get_json(silent=True) or {}

        # Sanitize email input
        email = sanitize_email(data.get("email", ""))
        if not email:
            app.logger.warning("api forgot missing email")
            return {"success": False, "error": "Email is required."}, 400

        user = User.query.filter_by(email=email).first()
        if user:
            reset_token = create_reset_token(user)
            app.logger.info("api forgot reset issued", extra={"user_id": user.id})

            # Send password reset email
            app_url = os.getenv("GOALIXA_APP_URL", "http://localhost:5000")
            email_sent = email_service.send_password_reset_email(
                to=email,
                reset_token=reset_token.token,
                app_url=app_url
            )

            if email_sent:
                app.logger.info("password reset email sent", extra={"user_id": user.id})
            else:
                app.logger.warning("password reset email failed", extra={"user_id": user.id})
        else:
            app.logger.info("api forgot unknown email", extra={"email": email})

        # Return generic success message (don't reveal if email exists)
        return {
            "success": True,
            "message": "If an account exists with this email, a password reset link has been sent.",
        }

    @app.route("/api/password-reset/request", methods=["POST"])
    @rate_limit(action="password_reset_request", limit=3, window_seconds=300, block_duration_seconds=900)
    def api_password_reset_request():
        """Alias endpoint used by PWA for password-reset request flow."""
        return api_forgot_password()

    @app.route("/api/password-reset/confirm", methods=["POST"])
    @app.route("/api/reset", methods=["POST"])
    @rate_limit(action="password_reset_confirm", limit=5, window_seconds=300, block_duration_seconds=900)
    def api_password_reset_confirm():
        """Confirm password reset with token + new password."""
        data = request.get_json(silent=True) or {}

        # Sanitize inputs
        token = sanitize_string_input(data.get("token", ""), max_length=256)
        password = sanitize_password(data.get("password", ""))

        if not token or not password:
            app.logger.warning("api password reset confirm missing fields")
            return {"success": False, "error": "Token and password are required."}, 400

        # Validate password complexity
        is_valid, error_msg = validate_password_complexity(password)
        if not is_valid:
            app.logger.warning("api password reset weak password")
            return {"success": False, "error": error_msg}, 400

        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        if not reset_token or not reset_token.is_valid():
            app.logger.warning("api password reset confirm invalid token")
            return {"success": False, "error": "Reset link is invalid or expired."}, 400

        reset_token.user.password_hash = generate_password_hash(password)
        reset_token.used_at = datetime.now(timezone.utc)
        from auth.models import db

        db.session.commit()

        # Send password reset confirmation email
        try:
            email_service.send_password_reset_confirmation_email(
                to=reset_token.user.email
            )
        except Exception as e:
            app.logger.warning(
                "password reset confirmation email failed",
                extra={"user_id": reset_token.user_id, "error": str(e)}
            )

        app.logger.info(
            "api password reset confirm success",
            extra={"user_id": reset_token.user_id},
        )
        return {"success": True, "message": "Password has been reset."}

    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        # Revoke refresh token if present
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        refresh_token_jwt = request.cookies.get(refresh_cookie_name)

        if refresh_token_jwt:
            payload, err = decode_refresh_token(
                refresh_token_jwt, app.config["AUTH_JWT_SECRET"]
            )
            if not err and payload and "jti" in payload:
                token = RefreshToken.query.filter_by(
                    token_id=payload["jti"]
                ).first()
                if token and token.is_valid():
                    token.revoke()
                    from auth.models import db

                    db.session.commit()
                    app.logger.info(
                        "revoked refresh token on logout",
                        extra={"token_id": payload["jti"]},
                    )

        app.logger.info("api logout")
        AUTH_LOGOUT_TOTAL.labels(status="success").inc()
        response = make_response({"success": True})
        # Clear both access and refresh cookies
        for cookie_name in [
            app.config["AUTH_ACCESS_COOKIE_NAME"],
            app.config["AUTH_REFRESH_COOKIE_NAME"],
        ]:
            response.delete_cookie(
                cookie_name,
                path="/",
                domain=app.config["AUTH_COOKIE_DOMAIN"],
                samesite=app.config["AUTH_COOKIE_SAMESITE"],
            )
        return response

    @app.route("/api/sessions", methods=["GET"])
    @auth_required()
    def api_list_sessions():
        """List all active sessions for the current user."""
        tokens = get_user_active_tokens(g.current_user.id)
        sessions = [token.to_dict() for token in tokens]

        # Mark current session
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        current_refresh_token = request.cookies.get(refresh_cookie_name)
        if current_refresh_token:
            payload, err = decode_refresh_token(
                current_refresh_token, app.config["AUTH_JWT_SECRET"]
            )
            if not err and payload and "jti" in payload:
                for session in sessions:
                    # Use token_id to match (same as jti)
                    if session.get("id") == int(payload.get("jti", 0)):
                        session["is_current"] = True
                        break

        return {"success": True, "sessions": sessions}

    @app.route("/api/sessions/<int:token_id>/revoke", methods=["POST"])
    @auth_required()
    def api_revoke_session(token_id):
        """Revoke a specific session (refresh token)."""
        # Prevent revoking the current session through this endpoint
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        current_refresh_token = request.cookies.get(refresh_cookie_name)

        if current_refresh_token:
            payload, err = decode_refresh_token(
                current_refresh_token, app.config["AUTH_JWT_SECRET"]
            )
            if not err and payload and "jti" in payload:
                # Check if trying to revoke current session
                current_token_id = int(payload.get("jti", 0))
                if token_id == current_token_id:
                    return {
                        "success": False,
                        "error": "Cannot revoke current session. Use /api/logout instead."
                    }, 400

        # Find and revoke the token
        token = RefreshToken.query.filter_by(
            id=token_id,
            user_id=g.current_user.id
        ).first()

        if not token:
            return {"success": False, "error": "Session not found."}, 404

        if token.revoked_at:
            return {"success": False, "error": "Session already revoked."}, 400

        token.revoke()
        from auth.models import db

        db.session.commit()

        app.logger.info(
            "revoked session via API",
            extra={"user_id": g.current_user.id, "token_id": token_id},
        )

        return {"success": True, "message": "Session revoked successfully."}

    @app.route("/api/sessions/revoke-all", methods=["POST"])
    @auth_required()
    def api_revoke_all_sessions():
        """Revoke all sessions except the current one."""
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        current_refresh_token = request.cookies.get(refresh_cookie_name)

        current_token_id = None
        if current_refresh_token:
            payload, err = decode_refresh_token(
                current_refresh_token, app.config["AUTH_JWT_SECRET"]
            )
            if not err and payload and "jti" in payload:
                current_token_id = int(payload.get("jti", 0))

        # Revoke all tokens except current
        tokens = RefreshToken.query.filter_by(
            user_id=g.current_user.id,
            revoked_at=None
        ).all()

        revoked_count = 0
        for token in tokens:
            if token.id != current_token_id:
                token.revoke()
                revoked_count += 1

        from auth.models import db

        db.session.commit()

        app.logger.info(
            "revoked all sessions via API",
            extra={"user_id": g.current_user.id, "revoked_count": revoked_count},
        )

        return {
            "success": True,
            "message": f"Revoked {revoked_count} session(s).",
            "revoked_count": revoked_count
        }

    @app.route("/admin/cleanup-tokens", methods=["POST"])
    def admin_cleanup_tokens():
        """Admin endpoint to clean up expired tokens."""
        # Simple API key check for admin access
        api_key = request.headers.get("X-Admin-API-Key")
        admin_key = os.getenv("ADMIN_CLEANUP_API_KEY", "")

        if api_key != admin_key:
            return {"success": False, "error": "Unauthorized"}, 401

        days_to_keep = int(request.args.get("days", "7"))
        deleted = cleanup_expired_tokens(days_to_keep=days_to_keep)

        return {
            "success": True,
            "message": f"Cleaned up {deleted} expired tokens.",
            "deleted_count": deleted
        }

    @app.route("/api/refresh", methods=["POST"])
    def api_refresh():
        """Exchange refresh token for new access token."""
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        refresh_token_jwt = request.cookies.get(refresh_cookie_name)

        if not refresh_token_jwt:
            app.logger.warning("api refresh missing cookie")
            AUTH_REFRESH_TOTAL.labels(status="failed_missing").inc()
            return {"success": False, "error": "Refresh token not found."}, 401

        # Decode refresh token JWT
        payload, err = decode_refresh_token(
            refresh_token_jwt, app.config["AUTH_JWT_SECRET"]
        )
        if err:
            app.logger.warning("api refresh decode failed", extra={"reason": err})
            AUTH_REFRESH_TOTAL.labels(status="failed_invalid").inc()
            return {"success": False, "error": "Invalid refresh token."}, 401

        if not payload or "sub" not in payload or "jti" not in payload:
            app.logger.warning("api refresh invalid payload")
            AUTH_REFRESH_TOTAL.labels(status="failed_invalid").inc()
            return {"success": False, "error": "Invalid refresh token."}, 401

        # Check database for token validity
        from auth.models import db

        try:
            user_id = int(payload.get("sub"))
        except (TypeError, ValueError):
            app.logger.warning("api refresh invalid user_id", extra={"sub": payload.get("sub")})
            AUTH_REFRESH_TOTAL.labels(status="failed_invalid").inc()
            return {"success": False, "error": "Invalid refresh token."}, 401

        refresh_token = RefreshToken.query.filter_by(
            token_id=payload["jti"], user_id=user_id
        ).first()

        if not refresh_token or not refresh_token.is_valid():
            app.logger.warning(
                "api refresh token invalid or revoked",
                extra={"token_id": payload["jti"], "user_id": user_id},
            )
            AUTH_REFRESH_TOTAL.labels(status="failed_expired").inc()
            return {"success": False, "error": "Invalid or expired refresh token."}, 401

        user = User.query.get(user_id)
        if not user or not user.active:
            app.logger.warning(
                "api refresh user not found or inactive",
                extra={"user_id": user_id},
            )
            AUTH_REFRESH_TOTAL.labels(status="failed_user_inactive").inc()
            return {"success": False, "error": "User not found or inactive."}, 401

        # Create new access token
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"],
        )

        # Rotate refresh token (issue new one, revoke old)
        # Get device info from the old token to preserve it
        device_info = {
            "device_name": refresh_token.device_name,
            "device_type": refresh_token.device_type,
            "device_id": refresh_token.device_id,
            "user_agent": refresh_token.user_agent,
            "ip_address": refresh_token.ip_address,
        }

        # Update last_seen_at on old token before revoking
        refresh_token.last_seen_at = datetime.now(timezone.utc)

        new_refresh_token_str = create_refresh_token_string()
        new_refresh_token_jwt = create_refresh_token_jwt(
            user_id=user.id,
            token_id=new_refresh_token_str,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"],
        )

        # Create new refresh token record with preserved device info
        new_refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"]
        )
        new_db_token = RefreshToken(
            token=new_refresh_token_str,
            token_id=new_refresh_token_str,
            user_id=user.id,
            expires_at=new_refresh_expires,
            device_name=device_info.get("device_name"),
            device_type=device_info.get("device_type"),
            device_id=device_info.get("device_id"),
            user_agent=device_info.get("user_agent"),
            ip_address=device_info.get("ip_address"),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.session.add(new_db_token)

        # Revoke old refresh token
        refresh_token.revoke()
        refresh_token.replaced_by = new_db_token.id

        db.session.commit()

        app.logger.info(
            "api refresh success",
            extra={
                "user_id": user.id,
                "old_token_id": payload["jti"],
                "new_token_id": new_refresh_token_str,
            },
        )

        AUTH_REFRESH_TOTAL.labels(status="success").inc()

        # Set new cookies
        response = make_response({"success": True, "access_token": access_token})
        response.set_cookie(
            app.config["AUTH_ACCESS_COOKIE_NAME"],
            access_token,
            max_age=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"] * 60,
            httponly=True,
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
            secure=app.config["AUTH_COOKIE_SECURE"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
        )
        response.set_cookie(
            app.config["AUTH_REFRESH_COOKIE_NAME"],
            new_refresh_token_jwt,
            max_age=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"] * 86400,
            httponly=True,
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
            secure=app.config["AUTH_COOKIE_SECURE"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
        )

        return response

    @app.route("/api/me", methods=["GET"])
    def api_me():
        if g.current_user:
            return {
                "authenticated": True,
                "user": {
                    "id": g.current_user.id,
                    "email": g.current_user.email,
                },
            }
        return {"authenticated": False, "user": None}

    @app.route("/api/verify-email", methods=["POST"])
    def api_verify_email():
        """Verify email address with token."""
        data = request.get_json(silent=True) or {}
        token = str(data.get("token", "")).strip()

        if not token:
            app.logger.warning("api verify email missing token")
            return {"success": False, "error": "Token is required."}, 400

        # Verify token against database
        verification_token = EmailVerificationToken.query.filter_by(token=token).first()

        if not verification_token:
            app.logger.warning("api verify email invalid token", extra={"token": token[:8] + "..."})
            return {"success": False, "error": "Invalid or expired token."}, 400

        if not verification_token.is_valid():
            app.logger.warning("api verify email expired or used token", extra={
                "token_id": verification_token.id,
                "user_id": verification_token.user_id
            })
            return {"success": False, "error": "Token has expired or already used."}, 400

        # Mark token as used
        verification_token.used_at = datetime.utcnow()

        # Mark user email as verified
        user = User.query.get(verification_token.user_id)
        if user:
            user.email_verified = True
            from auth.models import db
            db.session.commit()
            app.logger.info("api verify email success", extra={"user_id": user.id})
            return {"success": True, "message": "Email verified successfully."}
        else:
            app.logger.error("api verify email user not found", extra={"user_id": verification_token.user_id})
            return {"success": False, "error": "User not found."}, 404

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=debug)
