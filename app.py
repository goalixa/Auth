import logging
import os
from datetime import datetime, timedelta, timezone
from time import time

from dotenv import load_dotenv
from flask import (
    Flask,
    g,
    make_response,
    request,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest

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
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data.db")
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
    app.config["AUTH_COOKIE_DOMAIN"] = get_config_value("AUTH_COOKIE_DOMAIN")
    # Default to True for secure cookies in production
    secure = get_config_value("AUTH_COOKIE_SECURE", "1") == "1"
    # When SameSite=None is used, Secure must be True for modern browsers
    if app.config["AUTH_COOKIE_SAMESITE"] is None:
        secure = True
    app.config["AUTH_COOKIE_SECURE"] = secure
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
        reset_token_value = None
        if user:
            reset_token = create_reset_token(user)
            reset_token_value = reset_token.token
            app.logger.info("api forgot reset issued", extra={"user_id": user.id})
        else:
            app.logger.info("api forgot unknown email", extra={"email": email})
        return {
            "success": True,
            "message": "If the account exists, a reset token is ready.",
            "reset_token": reset_token_value,
        }

    @app.route("/api/password-reset/request", methods=["POST"])
    def api_password_reset_request():
        """Alias endpoint used by PWA for password-reset request flow."""
        return api_forgot_password()

    @app.route("/api/password-reset/confirm", methods=["POST"])
    @app.route("/api/reset", methods=["POST"])
    def api_password_reset_confirm():
        """Confirm password reset with token + new password."""
        data = request.get_json(silent=True) or {}
        token = str(data.get("token", "")).strip()
        password = data.get("password", "")

        if not token or not password:
            app.logger.warning("api password reset confirm missing fields")
            return {"success": False, "error": "Token and password are required."}, 400

        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        if not reset_token or not reset_token.is_valid():
            app.logger.warning("api password reset confirm invalid token")
            return {"success": False, "error": "Reset link is invalid or expired."}, 400

        reset_token.user.password_hash = generate_password_hash(password)
        reset_token.used_at = datetime.now(timezone.utc)
        from auth.models import db

        db.session.commit()
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

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=debug)
