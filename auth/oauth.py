import os

from authlib.integrations.flask_client import OAuth
import logging


oauth = OAuth()
logger = logging.getLogger(__name__)


def init_oauth(app):
    oauth.init_app(app)
    client_id = app.config.get("GOOGLE_CLIENT_ID") or os.getenv("GOOGLE_CLIENT_ID")
    client_secret = app.config.get("GOOGLE_CLIENT_SECRET") or os.getenv("GOOGLE_CLIENT_SECRET")
    if client_id and client_secret:
        oauth.register(
            name="google",
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
            client_kwargs={"scope": "openid email profile"},
        )
        app.config["GOOGLE_OAUTH_ENABLED"] = True
        logger.info("google oauth enabled")
    else:
        app.config["GOOGLE_OAUTH_ENABLED"] = False
        logger.info("google oauth disabled")
    return oauth
