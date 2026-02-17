#!/usr/bin/env python3
"""
Fix SQLite auto-increment sequence issue for User table
Run this script to reset the user ID sequence to max(id) + 1
"""

import sqlite3
import os

DB_PATH = os.getenv("AUTH_DATABASE_URI", "sqlite:///data.db").replace("sqlite:///", "")
if not DB_PATH or DB_PATH == "data.db":
    DB_PATH = "/app/data.db"  # Default path in container

print(f"Database path: {DB_PATH}")

if not os.path.exists(DB_PATH):
    print(f"Error: Database file not found at {DB_PATH}")
    exit(1)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

# Get current max user ID
cursor.execute("SELECT MAX(id) FROM user")
max_id = cursor.fetchone()[0]
print(f"Current max user ID: {max_id if max_id else 0}")

# Get the SQLite sequence
cursor.execute("SELECT seq FROM sqlite_sequence WHERE name='user'")
seq_result = cursor.fetchone()

if seq_result:
    current_seq = seq_result[0]
    print(f"Current SQLite sequence: {current_seq}")

    if current_seq <= max_id:
        new_seq = max_id + 1
        print(f"Updating sequence to: {new_seq}")
        cursor.execute("UPDATE sqlite_sequence SET seq = ? WHERE name='user'", (new_seq,))
        conn.commit()
        print("✓ Sequence updated successfully!")
    else:
        print("✓ Sequence is already correct")
else:
    print("No sequence found for user table, creating one...")
    cursor.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('user', ?)", (max_id + 1,))
    conn.commit()
    print("✓ Sequence created successfully!")

# Verify
cursor.execute("SELECT seq FROM sqlite_sequence WHERE name='user'")
new_seq = cursor.fetchone()[0]
print(f"New sequence value: {new_seq}")

conn.close()

print("\nYou can now try registering a new user!")
