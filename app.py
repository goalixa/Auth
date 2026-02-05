import logging
import os
import uuid
from datetime import datetime, timedelta
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
from auth.jwt import create_token, decode_token
from auth.models import PasswordResetToken, User, create_reset_token, init_db
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
    app.config["AUTH_JWT_TTL_MINUTES"] = int(get_config_value("AUTH_JWT_TTL_MINUTES", "120"))
    app.config["AUTH_COOKIE_NAME"] = os.getenv("AUTH_COOKIE_NAME", "goalixa_auth")
    app.config["AUTH_COOKIE_SAMESITE"] = get_config_value("AUTH_COOKIE_SAMESITE", "Lax")
    goalixa_app_url = normalize_app_url(get_config_value("GOALIXA_APP_URL", "https://goalixa.com/app"))
    cookie_domain = get_config_value("AUTH_COOKIE_DOMAIN")
    if cookie_domain is None:
        host = urlparse(goalixa_app_url).hostname or ""
        if host.endswith("goalixa.com"):
            cookie_domain = "goalixa.com"
    app.config["AUTH_COOKIE_DOMAIN"] = cookie_domain
    app.config["AUTH_COOKIE_SECURE"] = get_config_value("AUTH_COOKIE_SECURE", "0") == "1"
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
        """Remove auth cookie for both configured domain and host-only to avoid sticky invalid cookies."""
        cookie_name = app.config["AUTH_COOKIE_NAME"]
        domains = [app.config["AUTH_COOKIE_DOMAIN"]]
        if app.config["AUTH_COOKIE_DOMAIN"] is not None:
            domains.append(None)  # also clear host-only variant
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
        cookie_name = app.config["AUTH_COOKIE_NAME"]
        token = request.cookies.get(cookie_name)
        g.current_user = None
        g.clear_auth_cookie = False

        # Skip auth check for logout endpoint - it should work even without valid token
        if request.endpoint == "logout":
            return

        if not token:
            app.logger.info(
                "auth cookie missing",
                extra={"cookie_name": cookie_name, "path": request.path},
            )
            return
        payload, err = decode_token(token, app.config["AUTH_JWT_SECRET"])
        if err:
            app.logger.warning(
                "jwt decode failed",
                extra={"reason": err, "path": request.path},
            )
            g.clear_auth_cookie = True
            if request.endpoint != "login":
                return redirect(url_for("login"))
            return
        if not payload or "sub" not in payload:
            app.logger.warning("jwt payload missing sub", extra={"path": request.path})
            g.clear_auth_cookie = True
            if request.endpoint != "login":
                return redirect(url_for("login"))
            return
        try:
            user_id = int(payload.get("sub"))
        except (TypeError, ValueError):
            app.logger.warning("jwt sub is not a valid integer", extra={"sub": payload.get("sub"), "path": request.path})
            g.clear_auth_cookie = True
            if request.endpoint != "login":
                return redirect(url_for("login"))
            return
        g.current_user = User.query.get(user_id)
        if not g.current_user:
            app.logger.warning(
                "user not found for token",
                extra={"sub": user_id, "path": request.path},
            )
            g.clear_auth_cookie = True
            if request.endpoint != "login":
                return redirect(url_for("login"))
            return
        app.logger.info(
            "auth user loaded",
            extra={"user_id": g.current_user.id, "path": request.path},
        )

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
        app.logger.info(
            "request complete",
            extra={
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
                "remote_addr": request.headers.get("X-Forwarded-For", request.remote_addr),
            },
        )
        return response

    def issue_auth_response(user, next_url=None):
        token = create_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_JWT_TTL_MINUTES"],
        )
        app.logger.info(
            "issued auth response",
            extra={"user_id": user.id, "email": user.email, "next": next_url},
        )
        target = next_url or app.config["GOALIXA_APP_URL"]
        response = make_response(redirect(target))
        max_age = app.config["AUTH_JWT_TTL_MINUTES"] * 60
        response.set_cookie(
            app.config["AUTH_COOKIE_NAME"],
            token,
            max_age=max_age,
            httponly=True,
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
            secure=app.config["AUTH_COOKIE_SECURE"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
        )
        return response

    def issue_auth_json_response(user):
        app.logger.info(
            "issued auth json response",
            extra={"user_id": user.id, "email": user.email},
        )
        response = make_response({"success": True, "user": {"email": user.email}})
        max_age = app.config["AUTH_JWT_TTL_MINUTES"] * 60
        response.set_cookie(
            app.config["AUTH_COOKIE_NAME"],
            create_token(
                user_id=user.id,
                email=user.email,
                secret=app.config["AUTH_JWT_SECRET"],
                ttl_minutes=app.config["AUTH_JWT_TTL_MINUTES"],
            ),
            max_age=max_age,
            httponly=True,
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
            secure=app.config["AUTH_COOKIE_SECURE"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
        )
        return response

    def send_ui(filename):
        return send_from_directory(UI_DIR, filename)

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
        app.logger.info("api logout")
        response = make_response({"success": True})
        response.delete_cookie(
            app.config["AUTH_COOKIE_NAME"],
            path="/",
            domain=app.config["AUTH_COOKIE_DOMAIN"],
            samesite=app.config["AUTH_COOKIE_SAMESITE"],
        )
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        next_url = request.args.get("next")
        error = None
        if request.method == "GET":
            if g.current_user:
                return redirect(app.config["GOALIXA_APP_URL"])
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
        response.delete_cookie(
            app.config["AUTH_COOKIE_NAME"],
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
            reset_token.used_at = datetime.utcnow()
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
        if next_url:
            session["oauth_next"] = next_url
        app.logger.info("google oauth login start", extra={"next": next_url})
        redirect_uri = app.config.get("GOOGLE_REDIRECT_URI") or url_for(
            "google_callback", _external=True
        )
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route("/login/google/callback", methods=["GET"])
    def google_callback():
        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            return abort(404)
        token = oauth.google.authorize_access_token()
        if not token:
            app.logger.warning("google oauth missing token")
            return redirect(url_for("login"))
        # Try to get user info from ID token, fall back to userinfo endpoint
        user_info = None
        try:
            user_info = oauth.google.parse_id_token(token)
        except Exception:
            user_info = oauth.google.get("userinfo").json()
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
        next_url = session.pop("oauth_next", None)
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
