import os
import uuid
from datetime import datetime, timedelta
from urllib.parse import urlencode

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    g,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

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


def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("AUTH_SECRET_KEY", "dev-auth-secret")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "AUTH_DATABASE_URI", f"sqlite:///{DB_PATH}"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["AUTH_JWT_SECRET"] = os.getenv("AUTH_JWT_SECRET", "dev-jwt-secret")
    app.config["AUTH_JWT_TTL_MINUTES"] = int(os.getenv("AUTH_JWT_TTL_MINUTES", "120"))
    app.config["AUTH_COOKIE_NAME"] = os.getenv("AUTH_COOKIE_NAME", "goalixa_auth")
    app.config["AUTH_COOKIE_SECURE"] = os.getenv("AUTH_COOKIE_SECURE", "0") == "1"
    app.config["GOALIXA_APP_URL"] = os.getenv("GOALIXA_APP_URL", "http://localhost:5000")
    app.config["REGISTERABLE"] = os.getenv("REGISTERABLE", "1") == "1"

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    init_db(app)
    init_oauth(app)

    @app.before_request
    def load_user():
        cookie_name = app.config["AUTH_COOKIE_NAME"]
        token = request.cookies.get(cookie_name)
        g.current_user = None
        if not token:
            return
        payload = decode_token(token, app.config["AUTH_JWT_SECRET"])
        if not payload:
            return
        try:
            user_id = int(payload.get("sub"))
        except (TypeError, ValueError):
            return
        g.current_user = User.query.get(user_id)

    def issue_auth_response(user, next_url=None):
        token = create_token(
            user_id=user.id,
            email=user.email,
            secret=app.config["AUTH_JWT_SECRET"],
            ttl_minutes=app.config["AUTH_JWT_TTL_MINUTES"],
        )
        target = next_url or app.config["GOALIXA_APP_URL"]
        response = make_response(redirect(target))
        max_age = app.config["AUTH_JWT_TTL_MINUTES"] * 60
        response.set_cookie(
            app.config["AUTH_COOKIE_NAME"],
            token,
            max_age=max_age,
            httponly=True,
            samesite="Lax",
            secure=app.config["AUTH_COOKIE_SECURE"],
        )
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

    @app.route("/login", methods=["GET", "POST"])
    def login():
        form = LoginForm()
        next_url = request.args.get("next")
        error = None
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            user = User.query.filter_by(email=email).first()
            if not user or not check_password_hash(user.password_hash, form.password.data):
                error = "Invalid email or password."
            elif not user.active:
                error = "Your account is inactive."
            else:
                return issue_auth_response(user, next_url=next_url)
        return render_template(
            "security/login.html",
            form=form,
            error=error,
            next_url=next_url,
            registerable=app.config["REGISTERABLE"],
            google_oauth_enabled=app.config.get("GOOGLE_OAUTH_ENABLED", False),
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if not app.config["REGISTERABLE"]:
            return abort(404)
        form = RegisterForm()
        next_url = request.args.get("next")
        error = None
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            existing = User.query.filter_by(email=email).first()
            if existing:
                error = "Email already registered."
            else:
                user = User(
                    email=email,
                    password_hash=generate_password_hash(form.password.data),
                )
                from auth.models import db

                db.session.add(user)
                db.session.commit()
                return issue_auth_response(user, next_url=next_url)
        return render_template(
            "security/register.html",
            form=form,
            error=error,
            next_url=next_url,
        )

    @app.route("/logout", methods=["GET"])
    def logout():
        next_url = request.args.get("next") or app.config["GOALIXA_APP_URL"]
        response = make_response(redirect(next_url))
        response.delete_cookie(app.config["AUTH_COOKIE_NAME"])
        return response

    @app.route("/forgot", methods=["GET", "POST"])
    def forgot_password():
        form = ForgotPasswordForm()
        next_url = request.args.get("next")
        message = None
        reset_link = None
        if form.validate_on_submit():
            email = form.email.data.strip().lower()
            user = User.query.filter_by(email=email).first()
            if user:
                reset_token = create_reset_token(user)
                reset_link = url_for(
                    "reset_password", token=reset_token.token, next=next_url, _external=True
                )
            message = "If the account exists, a reset link is ready."
        return render_template(
            "security/forgot_password.html",
            form=form,
            message=message,
            reset_link=reset_link,
            next_url=next_url,
        )

    @app.route("/reset/<token>", methods=["GET", "POST"])
    def reset_password(token):
        form = ResetPasswordForm()
        next_url = request.args.get("next")
        reset_token = PasswordResetToken.query.filter_by(token=token).first()
        error = None
        if not reset_token or not reset_token.is_valid():
            error = "Reset link is invalid or expired."
        if form.validate_on_submit() and not error:
            reset_token.user.password_hash = generate_password_hash(form.password.data)
            reset_token.used_at = datetime.utcnow()
            from auth.models import db

            db.session.commit()
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
            else:
                g.current_user.password_hash = generate_password_hash(form.new_password.data)
                from auth.models import db

                db.session.commit()
                message = "Password updated."
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
        redirect_uri = os.getenv("GOOGLE_REDIRECT_URI") or url_for(
            "google_callback", _external=True
        )
        return oauth.google.authorize_redirect(redirect_uri)

    @app.route("/login/google/callback", methods=["GET"])
    def google_callback():
        if not app.config.get("GOOGLE_OAUTH_ENABLED"):
            return abort(404)
        token = oauth.google.authorize_access_token()
        if not token:
            return redirect(url_for("login"))
        user_info = oauth.google.parse_id_token(token)
        if not user_info:
            user_info = oauth.google.get("userinfo").json()
        email = (user_info or {}).get("email")
        if not email:
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
        next_url = session.pop("oauth_next", None)
        return issue_auth_response(user, next_url=next_url)

    @app.errorhandler(OAuthError)
    def handle_oauth_error(error):
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

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5001"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=debug)
