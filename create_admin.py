"""
Script to create an admin user for the admin panel.

Usage:
    python create_admin.py admin@example.com password123
"""
import sys
import os
from datetime import datetime

# Add the goalixa-auth path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from werkzeug.security import generate_password_hash

# Set up the Flask app and database
os.chdir('/Users/snapp/Desktop/projects/Goalixa/Services/goalixa-auth')

from app import app
from auth.models import db, User, SyntraUser


def create_admin_user(email: str, password: str):
    with app.app_context():
        # Check if user exists
        user = User.query.filter_by(email=email).first()

        if user:
            print(f"User {email} already exists, updating password...")
            user.password_hash = generate_password_hash(password)
        else:
            print(f"Creating user {email}...")
            user = User(
                email=email,
                password_hash=generate_password_hash(password),
            )
            db.session.add(user)

        db.session.commit()

        # Check if SyntraUser exists with admin role
        syntra_user = SyntraUser.query.filter_by(user_id=user.id).first()

        if syntra_user:
            print(f"SyntraUser already exists, updating role to admin...")
            syntra_user.role = 'admin'
            syntra_user.active = True
        else:
            print(f"Creating SyntraUser with admin role...")
            syntra_user = SyntraUser(
                user_id=user.id,
                role='admin',
                active=True,
            )
            db.session.add(syntra_user)

        db.session.commit()

        print(f"✅ Admin user created successfully!")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        print(f"   Role: admin")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python create_admin.py <email> <password>")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]
    create_admin_user(email, password)