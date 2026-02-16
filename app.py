import base64
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from time import time
from urllib.parse import urlencode, urlparse, urlunparse

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

from auth.forms import (
    ChangePasswordForm,
    ForgotPasswordForm,
    LoginForm,
    RegisterForm,
    ResetPasswordForm,
)
from auth.jwt import (
    create_access_token,
    create_refresh_token_jwt,
    create_refresh_token_string,
    decode_access_token,
    decode_refresh_token,
)
from auth.models import (
    PasswordResetToken,
    RefreshToken,
    User,
    create_reset_token,
    init_db,
    revoke_all_user_tokens,
)
from auth.oauth import init_oauth, oauth
from authlib.integrations.base_client.errors import OAuthError

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data.db")
UI_DIR = os.path.join(BASE_DIR, "auth-ui")
SECRETS_DIR = "/run/secrets"


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
    3) hard-coded dev fallback
    """
    return (
        get_config_value("AUTH_JWT_SECRET")
        or get_config_value("AUTH_SECRET_KEY")
        or "dev-jwt-secret"
    )


def normalize_app_url(url):
    """Ensure GOALIXA_APP_URL ends with a trailing slash to avoid path rewrite issues behind proxies."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    if not path.endswith("/"):
        path = f"{path}/"
    parsed = parsed._replace(path=path)
    return urlunparse(parsed)

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "http_status"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)
INPROGRESS_REQUESTS = Gauge(
    "http_requests_inprogress",
    "In progress HTTP requests",
)


def create_app():
    load_dotenv()
    app = Flask(__name__)
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    app.logger.setLevel(log_level)
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
    goalixa_app_url = normalize_app_url(get_config_value("GOALIXA_APP_URL", "https://goalixa.com/app"))
    cookie_domain = get_config_value("AUTH_COOKIE_DOMAIN")
    if cookie_domain is None:
        host = urlparse(goalixa_app_url).hostname or ""
        if host.endswith("goalixa.com"):
            # Leading dot is required for cookies to work across all subdomains
            cookie_domain = ".goalixa.com"
    app.config["AUTH_COOKIE_DOMAIN"] = cookie_domain
    # Default to True for secure cookies in production
    secure = get_config_value("AUTH_COOKIE_SECURE", "1") == "1"
    # When SameSite=None is used, Secure must be True for modern browsers
    if app.config["AUTH_COOKIE_SAMESITE"] is None:
        secure = True
    app.config["AUTH_COOKIE_SECURE"] = secure
    # Configure Flask session cookie (used for OAuth state) with same security settings
    app.config["SESSION_COOKIE_SECURE"] = app.config["AUTH_COOKIE_SECURE"]
    app.config["SESSION_COOKIE_SAMESITE"] = app.config["AUTH_COOKIE_SAMESITE"]
    app.config["SESSION_COOKIE_DOMAIN"] = app.config["AUTH_COOKIE_DOMAIN"]
    app.config["GOALIXA_APP_URL"] = goalixa_app_url
    app.config["GOOGLE_CLIENT_ID"] = get_config_value("GOOGLE_CLIENT_ID")
    app.config["GOOGLE_CLIENT_SECRET"] = get_config_value("GOOGLE_CLIENT_SECRET")
    app.config["GOOGLE_REDIRECT_URI"] = get_config_value("GOOGLE_REDIRECT_URI")
    app.config["REGISTERABLE"] = os.getenv("REGISTERABLE", "1") == "1"

    app.logger.info(
        "app configured",
        extra={
            "registerable": app.config["REGISTERABLE"],
            "cookie_secure": app.config["AUTH_COOKIE_SECURE"],
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
            "health",
            "metrics",
            "ui_root",
            "static",
            "login",
            "register",
            "logout",
            "forgot_password",
            "reset_password",
            "google_login",
            "google_callback",
            "api_login",
            "api_register",
            "api_forgot_password",
            "api_logout",
            "api_me",
            "api_refresh",
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
        if request.endpoint != "login":
            return redirect(url_for("login"))
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

    def issue_auth_response(user, next_url=None):
        # Create access token
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"],
        )

        # Create refresh token
        from auth.models import db

        refresh_token_str = create_refresh_token_string()
        refresh_token_jwt = create_refresh_token_jwt(
            user_id=user.id,
            token_id=refresh_token_str,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"],
        )

        # Store refresh token in database
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"]
        )
        refresh_token = RefreshToken(
            token=refresh_token_str,
            token_id=refresh_token_str,
            user_id=user.id,
            expires_at=refresh_expires,
        )
        db.session.add(refresh_token)
        db.session.commit()

        app.logger.info(
            "issued auth response with dual tokens",
            extra={"user_id": user.id, "email": user.email, "next": next_url},
        )
        target = next_url or app.config["GOALIXA_APP_URL"]
        access_max_age = app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"] * 60
        refresh_max_age = app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"] * 86400

        # Check if target is an external URL (different domain)
        target_domain = urlparse(target).hostname or ""
        current_domain = request.host.split(":")[0]  # Remove port if present

        app.logger.info(
            "redirect check",
            extra={
                "target": target,
                "target_domain": target_domain,
                "current_domain": current_domain,
                "is_external": target_domain and target_domain != current_domain,
            },
        )

        # For external redirects, use JavaScript redirect to ensure cookie is set
        if target_domain and target_domain != current_domain:
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirecting...</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }}
        .container {{
            text-align: center;
            padding: 2rem;
        }}
        .spinner {{
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 1rem;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <p>Redirecting you to the application...</p>
    </div>
    <script>
        // Small delay to ensure cookie is set before redirect
        setTimeout(function() {{
            window.location.href = {repr(target)};
        }}, 100);
    </script>
</body>
</html>"""
            response = make_response(html)
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

        # For internal redirects, use HTTP redirect
        response = make_response(redirect(target))
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
        # Create access token
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"],
        )

        # Create refresh token
        from auth.models import db

        refresh_token_str = create_refresh_token_string()
        refresh_token_jwt = create_refresh_token_jwt(
            user_id=user.id,
            token_id=refresh_token_str,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"],
        )

        # Store refresh token in database
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"]
        )
        refresh_token = RefreshToken(
            token=refresh_token_str,
            token_id=refresh_token_str,
            user_id=user.id,
            expires_at=refresh_expires,
        )
        db.session.add(refresh_token)
        db.session.commit()

        app.logger.info(
            "issued auth json response with dual tokens",
            extra={"user_id": user.id, "email": user.email},
        )
        response = make_response({"success": True, "user": {"email": user.email}})
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

    def send_ui(filename):
        response = send_from_directory(UI_DIR, filename)
        # Add cache-busting headers to prevent browser caching
        if hasattr(response, 'headers'):
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        return response

    def require_login(next_url=None):
        if g.current_user:
            return None
        login_url = url_for("login")
        if next_url:
            login_url = f"{login_url}?{urlencode({'next': next_url})}"
        return redirect(login_url)

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
    def ui_root():
        return send_ui("index.html")

    @app.route("/dashboard", methods=["GET"])
    def dashboard():
        if not g.current_user:
            return redirect(url_for("login"))
        return redirect(app.config["GOALIXA_APP_URL"])

    @app.route("/api/login", methods=["POST"])
    def api_login():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        password = data.get("password", "")
        if not email or not password:
            app.logger.warning("api login missing credentials")
            return {"success": False, "error": "Email and password are required."}, 400
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            app.logger.warning("api login invalid credentials", extra={"email": email})
            return {"success": False, "error": "Invalid email or password."}, 401
        if not user.active:
            app.logger.warning("api login inactive user", extra={"user_id": user.id})
            return {"success": False, "error": "Your account is inactive."}, 403
        return issue_auth_json_response(user)

    @app.route("/api/register", methods=["POST"])
    def api_register():
        if not app.config["REGISTERABLE"]:
            app.logger.warning("api register disabled")
            return {"success": False, "error": "Registration is disabled."}, 403
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        password = data.get("password", "")
        if not email or not password:
            app.logger.warning("api register missing credentials")
            return {"success": False, "error": "Email and password are required."}, 400
        existing = User.query.filter_by(email=email).first()
        if existing:
            app.logger.warning("api register email exists", extra={"email": email})
            return {"success": False, "error": "Email already registered."}, 409
        user = User(
            email=email,
            password_hash=generate_password_hash(password),
        )
        from auth.models import db

        db.session.add(user)
        db.session.commit()
        app.logger.info("api register success", extra={"user_id": user.id, "email": email})
        return issue_auth_json_response(user)

    @app.route("/api/forgot", methods=["POST"])
    def api_forgot_password():
        data = request.get_json(silent=True) or {}
        email = str(data.get("email", "")).strip().lower()
        if not email:
            app.logger.warning("api forgot missing email")
            return {"success": False, "error": "Email is required."}, 400
        user = User.query.filter_by(email=email).first()
        reset_link = None
        if user:
            reset_token = create_reset_token(user)
            reset_link = url_for(
                "reset_password", token=reset_token.token, _external=True
            )
            app.logger.info("api forgot reset issued", extra={"user_id": user.id})
        else:
            app.logger.info("api forgot unknown email", extra={"email": email})
        return {
            "success": True,
            "message": "If the account exists, a reset link is ready.",
            "reset_link": reset_link,
        }

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

    @app.route("/api/refresh", methods=["POST"])
    def api_refresh():
        """Exchange refresh token for new access token."""
        refresh_cookie_name = app.config["AUTH_REFRESH_COOKIE_NAME"]
        refresh_token_jwt = request.cookies.get(refresh_cookie_name)

        if not refresh_token_jwt:
            app.logger.warning("api refresh missing cookie")
            return {"success": False, "error": "Refresh token not found."}, 401

        # Decode refresh token JWT
        payload, err = decode_refresh_token(
            refresh_token_jwt, app.config["AUTH_JWT_SECRET"]
        )
        if err:
            app.logger.warning("api refresh decode failed", extra={"reason": err})
            return {"success": False, "error": "Invalid refresh token."}, 401

        if not payload or "sub" not in payload or "jti" not in payload:
            app.logger.warning("api refresh invalid payload")
            return {"success": False, "error": "Invalid refresh token."}, 401

        # Check database for token validity
        from auth.models import db

        try:
            user_id = int(payload.get("sub"))
        except (TypeError, ValueError):
            app.logger.warning("api refresh invalid user_id", extra={"sub": payload.get("sub")})
            return {"success": False, "error": "Invalid refresh token."}, 401

        refresh_token = RefreshToken.query.filter_by(
            token_id=payload["jti"], user_id=user_id
        ).first()

        if not refresh_token or not refresh_token.is_valid():
            app.logger.warning(
                "api refresh token invalid or revoked",
                extra={"token_id": payload["jti"], "user_id": user_id},
            )
            return {"success": False, "error": "Invalid or expired refresh token."}, 401

        user = User.query.get(user_id)
        if not user or not user.active:
            app.logger.warning(
                "api refresh user not found or inactive",
                extra={"user_id": user_id},
            )
            return {"success": False, "error": "User not found or inactive."}, 401

        # Create new access token
        access_token = create_access_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_ACCESS_TOKEN_TTL_MINUTES"],
        )

        # Rotate refresh token (issue new one, revoke old)
        new_refresh_token_str = create_refresh_token_string()
        new_refresh_token_jwt = create_refresh_token_jwt(
            user_id=user.id,
            token_id=new_refresh_token_str,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"],
        )

        # Create new refresh token record
        new_refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=app.config["AUTH_REFRESH_TOKEN_TTL_DAYS"]
        )
        new_db_token = RefreshToken(
            token=new_refresh_token_str,
            token_id=new_refresh_token_str,
            user_id=user.id,
            expires_at=new_refresh_expires,
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

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        next_url = request.args.get("next")
        error = None
        if request.method == "GET":
            if g.current_user:
                # Use next parameter if provided, otherwise use default app URL
                return redirect(next_url or app.config["GOALIXA_APP_URL"])
            return send_ui("index.html")
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, form.password.data):
                error = "Invalid email or password."
                app.logger.warning("login invalid credentials", extra={"email": email})
            elif not user.active:
                error = "Your account is inactive."
                app.logger.warning("login inactive user", extra={"user_id": user.id})
            else:
                app.logger.info("login success", extra={"user_id": user.id, "email": email})
                return issue_auth_response(user, next_url=next_url)
        return send_ui("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if not app.config["REGISTERABLE"]:
            return abort(404)
        form = RegisterForm()
        next_url = request.args.get("next")
        error = None
        if request.method == "GET":
            return send_ui("signup.html")
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            existing = User.query.filter_by(email=email).first()
            if existing:
                error = "Email already registered."
                app.logger.warning("register email exists", extra={"email": email})
            else:
                user = User(
                    email=email,
                    password_hash=generate_password_hash(form.password.data),
                )
                from auth.models import db

                db.session.add(user)
                db.session.commit()
                app.logger.info("register success", extra={"user_id": user.id, "email": email})
                return issue_auth_response(user, next_url=next_url)
        return send_ui("signup.html")

    @app.route("/logout", methods=["GET"])
    def logout():
        next_url = request.args.get("next") or app.config["GOALIXA_APP_URL"]
        app.logger.info("logout", extra={"next": next_url})
        response = make_response(redirect(next_url))

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

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_password():
        form = ForgotPasswordForm()
        next_url = request.args.get("next")
        message = None
        reset_link = None
        if request.method == "GET":
            return send_ui("reset-password.html")
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            user = User.query.filter_by(email=email).first()
            if user:
                reset_token = create_reset_token(user)
                reset_link = url_for(
                    "reset_password", token=reset_token.token, next=next_url, _external=True
                )
                app.logger.info("forgot password reset issued", extra={"user_id": user.id})
            else:
                app.logger.info("forgot password unknown email", extra={"email": email})
            message = "If the account exists, a reset link is ready."
        return send_ui("reset-password.html")

    @app.route("/reset/<token>", methods=["GET", "POST"])
    def reset_password(token):
        form = ResetPasswordForm()
        next_url = request.args.get("next")
        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        error = None
        if not reset_token or not reset_token.is_valid():
            error = "Reset link is invalid or expired."
            app.logger.warning("reset password invalid token")
        if form.validate_on_submit() and not error:
            reset_token.user.password_hash = generate_password_hash(form.password.data)
            reset_token.used_at = datetime.now(timezone.utc)
            from auth.models import db

            db.session.commit()
            app.logger.info(
                "reset password success", extra={"user_id": reset_token.user_id}
            )
            return redirect(url_for("login", next=next_url))
        return render_template(
            "security/reset_password.html",
            form=form,
            token=token,
            error=error,
            next_url=next_url,
        )

    @app.route("/change-password", methods=["GET", "POST"])
    def change_password():
        next_url = request.args.get("next")
        if not g.current_user:
            return require_login(next_url or request.url)
        form = ChangePasswordForm()
        error = None
        message = None
        if form.validate_on_submit():
            if not check_password_hash(g.current_user.password_hash, form.password.data):
                error = "Current password is incorrect."
                app.logger.warning(
                    "change password invalid current password",
                    extra={"user_id": g.current_user.id},
                )
            else:
                g.current_user.password_hash = generate_password_hash(form.new_password.data)
                from auth.models import db

                db.session.commit()
                message = "Password updated."
                app.logger.info("change password success", extra={"user_id": g.current_user.id})
        return render_template(
            "security/change_password.html",
            form=form,
            error=error,
            message=message,
            next_url=next_url,
            app_url=app.config["GOALIXA_APP_URL"],
        )

    @app.route("/login/google", methods=["GET"])
    def google_login():
        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            return abort(404)
        next_url = request.args.get("next")
        # Encode next_url in the OAuth state parameter to avoid session cookie issues
        # Session cookies with SameSite=None may not be sent after OAuth redirect
        state = None
        if next_url:
            state = base64.urlsafe_b64encode(json.dumps({"next": next_url}).encode()).decode()
        app.logger.info("google oauth login start", extra={"next": next_url, "state": state})
        redirect_uri = app.config.get("GOOGLE_REDIRECT_URI") or url_for(
            "google_callback", _external=True
        )
        return oauth.google.authorize_redirect(redirect_uri, state=state)

    @app.route("/login/google/callback", methods=["GET"])
    def google_callback():
        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            return abort(404)
        try:
            token = oauth.google.authorize_access_token()
        except Exception as e:
            app.logger.warning(f"google oauth token error: {e}")
            return redirect(url_for("login"))

        if not token:
            app.logger.warning("google oauth missing token")
            return redirect(url_for("login"))

        # Get user info from token
        user_info = token.get("userinfo")

        # If not in token, try userinfo endpoint
        if not user_info:
            try:
                response = oauth.google.get("https://www.googleapis.com/oauth2/v3/userinfo")
                user_info = response.json()
            except Exception as e:
                app.logger.warning(f"google oauth userinfo error: {e}")

        email = (user_info or {}).get("email")
        if not email:
            app.logger.warning("google oauth missing email")
            return redirect(url_for("login"))

        email = email.strip().lower()
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(
                email=email,
                password_hash=generate_password_hash(uuid.uuid4().hex),
            )
            from auth.models import db

            db.session.add(user)
            db.session.commit()
            app.logger.info("google oauth user created", extra={"user_id": user.id})
        app.logger.info("google oauth success", extra={"user_id": user.id, "email": email})

        # Decode next_url from OAuth state parameter (more reliable than session)
        next_url = None
        state = token.get("state") or request.args.get("state")
        if state:
            try:
                state_data = json.loads(base64.urlsafe_b64decode(state).decode())
                next_url = state_data.get("next")
                app.logger.info("oauth state decoded", extra={"next": next_url})
            except Exception as e:
                app.logger.warning(f"failed to decode oauth state: {e}")

        return issue_auth_response(user, next_url=next_url)

    @app.errorhandler(OAuthError)
    def handle_oauth_error(error):
        app.logger.warning(
            "oauth error",
            extra={"description": getattr(error, "description", str(error))},
        )
        return (
            render_template(
                "error.html",
                title="OAuth error",
                message="Google sign-in failed. Please try again.",
                details=getattr(error, "description", str(error)),
                action_url=url_for("login"),
                action_label="Back to sign in",
            ),
            400,
        )

    @app.route("/<path:filename>", methods=["GET"])
    def ui_assets(filename):
        ui_path = os.path.join(UI_DIR, filename)
        if os.path.isfile(ui_path):
            return send_ui(filename)
        return abort(404)

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=debug)
