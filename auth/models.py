import os
import uuid
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy
import logging


db = SQLAlchemy()
logger = logging.getLogger(__name__)

#
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    refresh_tokens = db.relationship("RefreshToken", back_populates="user", lazy="dynamic")
    email_verification_tokens = db.relationship("EmailVerificationToken", back_populates="user", lazy="dynamic")
    reset_tokens = db.relationship("PasswordResetToken", back_populates="user", lazy="dynamic")
    syntra_profile = db.relationship("SyntraUser", back_populates="user", uselist=False, cascade="all, delete-orphan")
    created_syntra_users = db.relationship("SyntraUser", foreign_keys="SyntraUser.created_by", backref="creator")


class SyntraUser(db.Model):
    """
    Syntra-specific user profile with role-based access control.

    Roles:
    - admin: Full access to all Syntra features
    - operator: Can execute DevOps operations
    - viewer: Read-only access to dashboards and reports
    """
    __tablename__ = "syntra_user"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False, default="operator")
    department = db.Column(db.String(100))
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    active = db.Column(db.Boolean, default=True)

    user = db.relationship("User", foreign_keys=[user_id], back_populates="syntra_profile")

    def to_dict(self):
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "email": self.user.email if self.user else None,
            "role": self.role,
            "department": self.department,
            "active": self.active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def is_valid_role(self) -> bool:
        """Check if the role is valid."""
        return self.role in {"admin", "operator", "viewer"}


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_token"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="reset_tokens")

    def is_valid(self):
        return self.used_at is None and self.expires_at >= datetime.utcnow()


def create_reset_token(user, ttl_minutes=30):
    token = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.session.add(reset_token)
    db.session.commit()
    logger.info("password reset token created", extra={"user_id": user.id})
    return reset_token


class EmailVerificationToken(db.Model):
    __tablename__ = "email_verification_token"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", back_populates="email_verification_tokens")

    def is_valid(self):
        return self.used_at is None and self.expires_at >= datetime.utcnow()


def create_email_verification_token(user, ttl_minutes=60):
    """Create an email verification token for a user."""
    token = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    verification_token = EmailVerificationToken(
        user_id=user.id, token=token, expires_at=expires_at
    )
    db.session.add(verification_token)
    db.session.commit()
    logger.info("email verification token created", extra={"user_id": user.id})
    return verification_token


class RefreshToken(db.Model):
    __tablename__ = "refresh_token"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    token_id = db.Column(db.String(36), unique=True, nullable=False)  # UUID for tracking
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    revoked_at = db.Column(db.DateTime)
    replaced_by = db.Column(db.Integer, db.ForeignKey("refresh_token.id"))

    # Device tracking for security
    device_name = db.Column(db.String(255))  # User-friendly device name
    device_type = db.Column(db.String(50))   # desktop, mobile, tablet
    device_id = db.Column(db.String(100))    # Device fingerprint
    user_agent = db.Column(db.String(500))   # Browser user agent
    ip_address = db.Column(db.String(45))    # IP address (supports IPv6)
    last_seen_at = db.Column(db.DateTime)    # Last activity timestamp

    user = db.relationship("User", back_populates="refresh_tokens")

    def is_valid(self):
        """Check if token is not expired and not revoked."""
        return self.revoked_at is None and self.expires_at >= datetime.utcnow()

    def revoke(self):
        """Mark token as revoked."""
        self.revoked_at = datetime.utcnow()

    def get_device_info(self):
        """Get human-readable device information."""
        device = self.device_name or "Unknown Device"
        if self.device_type:
            device += f" ({self.device_type})"
        return device

    def to_dict(self):
        """Convert token to dictionary for API responses."""
        return {
            "id": self.id,
            "device": self.get_device_info(),
            "device_type": self.device_type,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_current": self.revoked_at is None,
        }


def revoke_all_user_tokens(user_id):
    """Revoke all active refresh tokens for a user."""
    tokens = RefreshToken.query.filter_by(user_id=user_id, revoked_at=None).all()
    for token in tokens:
        token.revoke()
    db.session.commit()
    logger.info(
        "revoked all user tokens",
        extra={"user_id": user_id, "count": len(tokens)},
    )


def cleanup_expired_tokens(days_to_keep=7):
    """
    Remove expired and revoked tokens older than specified days.

    Args:
        days_to_keep: Keep tokens for this many days after expiry/revocation

    Returns:
        Number of tokens cleaned up
    """
    cutoff = datetime.utcnow() - timedelta(days=days_to_keep)
    deleted = RefreshToken.query.filter(
        db.or_(
            RefreshToken.revoked_at < cutoff,
            RefreshToken.expires_at < cutoff
        )
    ).delete()
    db.session.commit()
    logger.info(
        "cleaned up expired tokens",
        extra={"deleted_count": deleted, "cutoff_days": days_to_keep}
    )
    return deleted


def get_user_active_tokens(user_id):
    """
    Get all active (non-revoked) tokens for a user.

    Args:
        user_id: User ID

    Returns:
        List of active RefreshToken objects
    """
    return RefreshToken.query.filter_by(
        user_id=user_id,
        revoked_at=None
    ).order_by(RefreshToken.created_at.desc()).all()


def count_user_active_tokens(user_id):
    """
    Count active tokens for a user.

    Args:
        user_id: User ID

    Returns:
        Number of active tokens
    """
    return RefreshToken.query.filter_by(
        user_id=user_id,
        revoked_at=None
    ).count()


def revoke_oldest_tokens(user_id, max_tokens=5):
    """
    Revoke oldest tokens exceeding the maximum allowed.

    Args:
        user_id: User ID
        max_tokens: Maximum number of active tokens to allow

    Returns:
        Number of tokens revoked
    """
    active_tokens = RefreshToken.query.filter_by(
        user_id=user_id,
        revoked_at=None
    ).order_by(RefreshToken.created_at.asc()).all()

    if len(active_tokens) <= max_tokens:
        return 0

    # Revoke oldest tokens
    to_revoke = active_tokens[:len(active_tokens) - max_tokens]
    for token in to_revoke:
        token.revoke()

    db.session.commit()
    logger.info(
        "revoked oldest tokens",
        extra={
            "user_id": user_id,
            "revoked_count": len(to_revoke),
            "max_tokens": max_tokens,
        }
    )
    return len(to_revoke)


def init_db(app):
    db.init_app(app)
    with app.app_context():
        logger.info("initializing database")
        db.create_all()
        admin_email = os.getenv("ADMIN_EMAIL")
        admin_password = os.getenv("ADMIN_PASSWORD")
        if admin_email and admin_password:
            from werkzeug.security import generate_password_hash

            if not User.query.filter_by(email=admin_email).first():
                user = User(
                    email=admin_email,
                    password_hash=generate_password_hash(admin_password),
                )
                db.session.add(user)
                db.session.commit()
                logger.info("admin user created", extra={"email": admin_email})
