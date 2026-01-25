from datetime import datetime, timedelta, timezone

import jwt
import logging


logger = logging.getLogger(__name__)


def create_token(user_id, email, secret, ttl_minutes):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token, secret):
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        logger.debug("jwt decode failed")
        return None
    return payload
