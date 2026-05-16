#!/usr/bin/env python3
"""Reset admin user password and ensure admin role."""
import os
import sys

# Add the path
sys.path.insert(0, '/Users/snapp/Desktop/projects/Goalixa/Services/goalixa-auth')

from werkzeug.security import generate_password_hash
from app import app
from auth.models import db, User, SyntraUser

with app.app_context():
    # Get or create user
    user = User.query.filter_by(email='admin@goalixa.local').first()

    if not user:
        user = User(
            email='admin@goalixa.local',
            password_hash=generate_password_hash('admin123')
        )
        db.session.add(user)
        db.session.commit()
        print("Created new user: admin@goalixa.local")
    else:
        # Update password
        user.password_hash = generate_password_hash('admin123')
        db.session.commit()
        print("Updated password for: admin@goalixa.local")

    # Ensure SyntraUser exists with admin role
    syntra = SyntraUser.query.filter_by(user_id=user.id).first()

    if not syntra:
        syntra = SyntraUser(
            user_id=user.id,
            role='admin',
            active=True
        )
        db.session.add(syntra)
        db.session.commit()
        print("Created SyntraUser with admin role")
    else:
        # Update role to admin
        syntra.role = 'admin'
        syntra.active = True
        db.session.commit()
        print("Updated SyntraUser to admin role")

    print("\n✅ Admin user ready!")
    print("   Email: admin@goalixa.local")
    print("   Password: admin123")
    print("   Role: admin")