#!/usr/bin/env python3
"""
Database migration script: SQLite -> PostgreSQL for goalixa-auth
"""

import os
import sys
from datetime import datetime

# Add app directory to path
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app, db
from auth.models import (
    User, SyntraUser, RefreshToken, EmailVerificationToken, PasswordResetToken
)
from migration_helper import export_sqlite_data, validate_migration, print_migration_status


def migrate_from_sqlite():
    """
    Main migration function: SQLite -> PostgreSQL
    """
    sqlite_db_path = os.getenv(
        "SQLITE_DB_PATH",
        os.path.join(os.path.dirname(__file__), "data.db")
    )

    print_migration_status(sqlite_db_path, os.getenv("AUTH_DATABASE_URI", "Not set"))

    # Step 1: Export SQLite data
    print("Step 1: Exporting data from SQLite...")
    sqlite_data = export_sqlite_data(sqlite_db_path)

    if not sqlite_data:
        print("⚠️  No data to migrate. Initializing fresh PostgreSQL database.")
        app = create_app()
        with app.app_context():
            db.create_all()
            print("✓ PostgreSQL database initialized")
        return

    # Step 2: Initialize Flask app with PostgreSQL
    print("\nStep 2: Initializing PostgreSQL connection...")
    app = create_app()

    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ PostgreSQL tables created")

        # Step 3: Migrate user data
        print("\nStep 3: Migrating user data...")
        if "user" in sqlite_data:
            for user_row in sqlite_data["user"]:
                user = User(
                    id=user_row.get("id"),
                    email=user_row.get("email"),
                    password_hash=user_row.get("password_hash"),
                    active=user_row.get("active", True),
                    email_verified=user_row.get("email_verified", False),
                    created_at=user_row.get("created_at")
                )
                db.session.add(user)
            db.session.commit()
            print(f"✓ Migrated {len(sqlite_data['user'])} users")

        # Step 4: Migrate refresh tokens
        print("Step 4: Migrating refresh tokens...")
        if "refresh_token" in sqlite_data:
            for token_row in sqlite_data["refresh_token"]:
                token = RefreshToken(
                    id=token_row.get("id"),
                    token=token_row.get("token"),
                    token_id=token_row.get("token_id"),
                    user_id=token_row.get("user_id"),
                    expires_at=token_row.get("expires_at"),
                    revoked_at=token_row.get("revoked_at"),
                    replaced_by=token_row.get("replaced_by"),
                    device_name=token_row.get("device_name"),
                    device_type=token_row.get("device_type"),
                    device_id=token_row.get("device_id"),
                    user_agent=token_row.get("user_agent"),
                    ip_address=token_row.get("ip_address"),
                    last_seen_at=token_row.get("last_seen_at"),
                    created_at=token_row.get("created_at")
                )
                db.session.add(token)
            db.session.commit()
            print(f"✓ Migrated {len(sqlite_data['refresh_token'])} refresh tokens")

        # Step 5: Migrate email verification tokens
        print("Step 5: Migrating email verification tokens...")
        if "email_verification_token" in sqlite_data:
            for token_row in sqlite_data["email_verification_token"]:
                token = EmailVerificationToken(
                    id=token_row.get("id"),
                    user_id=token_row.get("user_id"),
                    token=token_row.get("token"),
                    expires_at=token_row.get("expires_at"),
                    used_at=token_row.get("used_at"),
                    created_at=token_row.get("created_at")
                )
                db.session.add(token)
            db.session.commit()
            print(f"✓ Migrated {len(sqlite_data['email_verification_token'])} email tokens")

        # Step 6: Migrate password reset tokens
        print("Step 6: Migrating password reset tokens...")
        if "password_reset_token" in sqlite_data:
            for token_row in sqlite_data["password_reset_token"]:
                token = PasswordResetToken(
                    id=token_row.get("id"),
                    user_id=token_row.get("user_id"),
                    token=token_row.get("token"),
                    expires_at=token_row.get("expires_at"),
                    used_at=token_row.get("used_at"),
                    created_at=token_row.get("created_at")
                )
                db.session.add(token)
            db.session.commit()
            print(f"✓ Migrated {len(sqlite_data['password_reset_token'])} password reset tokens")

        # Step 7: Migrate syntra_user data (if exists)
        print("Step 7: Migrating syntra_user data...")
        if "syntra_user" in sqlite_data:
            for user_row in sqlite_data["syntra_user"]:
                user = SyntraUser(
                    id=user_row.get("id"),
                    user_id=user_row.get("user_id"),
                    role=user_row.get("role"),
                    department=user_row.get("department"),
                    created_by=user_row.get("created_by"),
                    active=user_row.get("active", True),
                    created_at=user_row.get("created_at")
                )
                db.session.add(user)
            db.session.commit()
            print(f"✓ Migrated {len(sqlite_data['syntra_user'])} syntra users")

        # Step 8: Validation
        print("\nStep 8: Validating migration...")
        if validate_migration(sqlite_data, db.engine.raw_connection()):
            print("\n" + "="*60)
            print("✓ MIGRATION COMPLETED SUCCESSFULLY")
            print("="*60)
            print(f"\nPostgreSQL database is ready for use.")
            print(f"You can now safely delete the SQLite database at: {sqlite_db_path}")
            return 0
        else:
            print("\n" + "="*60)
            print("❌ MIGRATION VALIDATION FAILED")
            print("="*60)
            return 1


if __name__ == "__main__":
    exit_code = migrate_from_sqlite()
    sys.exit(exit_code)
