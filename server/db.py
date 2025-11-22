import sqlite3
import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
import os

# SQLite file next to this script
DB_PATH = Path(__file__).resolve().parent / "pd_auth.db"

def now_iso():
    """Returns current UTC time in ISO 8601 format with 'Z'."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def connect():
    """Connects to the SQLite database and sets row factory to sqlite3.Row."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if not present, supporting Phase 4: Keypair and Challenge-Response."""
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY
    );
    """)

    # NOTE: device_hash (Phase 5) is removed from the devices table for Phase 4.
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      device_id TEXT NOT NULL,
      public_key BLOB,            -- raw bytes (Phase 3)
      device_info TEXT NOT NULL,  -- JSON string
      revoked INTEGER NOT NULL DEFAULT 0,
      registered_at TEXT NOT NULL,
      UNIQUE(username, device_id)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS challenges(
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      device_id TEXT NOT NULL,
      challenge BLOB NOT NULL,
      expires_at TEXT NOT NULL,
      consumed INTEGER NOT NULL DEFAULT 0
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions(
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      device_id TEXT NOT NULL,
      issued_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

# Ensure DB is initialized on import
init_db()


def register_device(username, device_id, device_info, public_key_bytes=None):
    """
    Register a user/device, creating a user if they don't exist, and storing the
    device's public key (Phase 3). Returns the stored device row as a dict.
    """
    conn = connect()
    cur = conn.cursor()
    device_info_json = json.dumps(device_info)

    # 1. Ensure user exists (Phase 1)
    cur.execute("INSERT OR IGNORE INTO users(username) VALUES(?)", (username,))

    # 2. Register/update device with public key (Phase 3)
    cur.execute("""
      INSERT OR REPLACE INTO devices(username, device_id, public_key, device_info, revoked, registered_at)
      VALUES(?, ?, ?, ?, 0, ?)
    """, (username, device_id, public_key_bytes, device_info_json, now_iso()))

    conn.commit()

    # 3. Retrieve the stored record
    cur.execute("""
      SELECT id, username, device_id, public_key, device_info, revoked, registered_at
      FROM devices WHERE username=? AND device_id=?
    """, (username, device_id))

    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_device_by_id(username, device_id):
    """
    Retrieve device data (including public key) for a given user/device_id.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      SELECT id, username, device_id, public_key, device_info, revoked, registered_at
      FROM devices WHERE username=? AND device_id=?
    """, (username, device_id))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def create_challenge(challenge_id, username, device_id, ttl_seconds=60):
    """
    Creates a new, unconsumed challenge for the user/device.
    Returns the stored challenge row as dict.
    """
    challenge_bytes = os.urandom(32) # The random bytes used for the challenge
    issued = datetime.utcnow()
    expires = issued + timedelta(seconds=ttl_seconds)

    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO challenges(id, username, device_id, challenge, expires_at, consumed)
      VALUES(?, ?, ?, ?, ?, 0)
    """, (challenge_id, username, device_id, challenge_bytes,
          expires.replace(microsecond=0).isoformat() + "Z"))
    conn.commit()
    cur.execute("SELECT id, username, device_id, challenge, expires_at FROM challenges WHERE id=?", (challenge_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_challenge(challenge_id):
    """
    Retrieves challenge data.
    """
    conn = connect()
    cur = conn.cursor()
    cur.execute("SELECT id, username, device_id, challenge, expires_at, consumed FROM challenges WHERE id=?", (challenge_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def mark_challenge_consumed(challenge_id):
    """Marks a challenge as used/consumed to prevent replay attacks."""
    conn = connect()
    cur = conn.cursor()
    cur.execute("UPDATE challenges SET consumed=1 WHERE id=?", (challenge_id,))
    conn.commit()
    conn.close()


def create_session(session_id, username, device_id, ttl_seconds=3600):
    """Create a simple session; returns the stored row as dict."""
    issued = datetime.utcnow()
    expires = issued + timedelta(seconds=ttl_seconds)
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO sessions(id, username, device_id, issued_at, expires_at)
      VALUES(?, ?, ?, ?, ?)
    """, (session_id, username, device_id,
          issued.replace(microsecond=0).isoformat() + "Z",
          expires.replace(microsecond=0).isoformat() + "Z"))
    conn.commit()
    cur.execute("SELECT id, username, device_id, issued_at, expires_at FROM sessions WHERE id=?", (session_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def list_devices(username):
    """Lists all devices (active and revoked) for a user."""
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      SELECT device_id, device_info, revoked, registered_at
      FROM devices WHERE username=?
    """, (username,))
    rows = cur.fetchall()
    conn.close()

    devices = []
    for row in rows:
        device_data = dict(row)
        device_data["device_info"] = json.loads(device_data["device_info"])
        devices.append(device_data)

    return devices


def revoke_device(username, device_id, reason=None):
    """Marks a device as revoked. Returns True if a device was updated."""
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      UPDATE devices SET revoked=1 WHERE username=? AND device_id=? AND revoked=0
    """, (username, device_id))

    updated = cur.rowcount > 0
    conn.commit()
    conn.close()
    return updated