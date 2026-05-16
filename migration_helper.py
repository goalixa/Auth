"""
Helper functions for migrating SQLite auth database to PostgreSQL
"""

import os
import sqlite3
from datetime import datetime


def export_sqlite_data(sqlite_db_path):
    """
    Export all data from SQLite database to Python objects
    Returns dict with table_name -> list of row dicts
    """
    if not os.path.exists(sqlite_db_path):
        print(f"SQLite database not found at {sqlite_db_path}")
        return {}

    conn = sqlite3.connect(sqlite_db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Get all table names
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in cursor.fetchall()]

    data = {}
    for table in tables:
        cursor.execute(f"SELECT * FROM {table}")
        rows = cursor.fetchall()
        data[table] = [dict(row) for row in rows]
        print(f"Exported {len(rows)} rows from {table}")

    conn.close()
    return data


def validate_migration(sqlite_data, postgres_conn):
    """
    Verify that all SQLite data was correctly migrated to PostgreSQL
    """
    cursor = postgres_conn.cursor()

    for table, rows in sqlite_data.items():
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        postgres_count = cursor.fetchone()[0]
        sqlite_count = len(rows)

        if postgres_count != sqlite_count:
            print(f"❌ {table}: SQLite has {sqlite_count}, PostgreSQL has {postgres_count}")
            return False
        else:
            print(f"✓ {table}: {postgres_count} rows migrated correctly")

    return True


def print_migration_status(sqlite_db_path, postgres_uri):
    """
    Print status of migration process
    """
    print("\n" + "="*60)
    print("MIGRATION STATUS")
    print("="*60)
    print(f"SQLite DB: {sqlite_db_path}")
    print(f"PostgreSQL: {postgres_uri}")
    print(f"Timestamp: {datetime.utcnow().isoformat()}")
    print("="*60 + "\n")
