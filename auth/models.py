import os
import uuid
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_token"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="reset_tokens")

    def is_valid(self):
        return self.used_at is None and self.expires_at >= datetime.utcnow()


def create_reset_token(user, ttl_minutes=30):
    token = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expires_at)
    db.session.add(reset_token)
    db.session.commit()
    return reset_token


def init_db(app):
    db.init_app(app)
    with app.app_context():
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
