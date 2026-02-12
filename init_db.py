#!/usr/bin/env python
"""
Initialize the auth database and create admin user.
Run this script before starting the auth service for the first time.
"""
import os
import sys

# Add the parent directory to the path so we can import from app
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

# Load environment variables
load_dotenv()

from app import create_app
from auth.models import db, User

def init_database():
    """Initialize database tables and create admin user."""
    app = create_app()

    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("Database tables created successfully!")

        # Create admin user if credentials are provided
        admin_email = os.getenv("ADMIN_EMAIL")
        admin_password = os.getenv("ADMIN_PASSWORD")

        if admin_email and admin_password:
            existing_user = User.query.filter_by(email=admin_email).first()
            if not existing_user:
                print(f"Creating admin user: {admin_email}")
                user = User(
                    email=admin_email,
                    password_hash=generate_password_hash(admin_password),
                )
                db.session.add(user)
                db.session.commit()
                print(f"Admin user created successfully!")
                print(f"  Email: {admin_email}")
                print(f"  Password: {admin_password}")
            else:
                print(f"Admin user already exists: {admin_email}")
        else:
            print("No ADMIN_EMAIL or ADMIN_PASSWORD found in environment.")
            print("Set these in .env file to create an admin user automatically.")
            print("Or register a new user via the /register endpoint (if REGISTERABLE=1)")

        # Show all users
        users = User.query.all()
        print(f"\nTotal users in database: {len(users)}")
        for user in users:
            print(f"  - ID: {user.id}, Email: {user.email}, Active: {user.active}")

if __name__ == "__main__":
    init_database()
