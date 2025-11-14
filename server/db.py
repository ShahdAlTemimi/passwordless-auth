import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta

# SQLite file next to this script
DB_PATH = Path(__file__).resolve().parent / "pd_auth.db"

def now_iso():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def connect():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Create tables if not present."""
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      username TEXT PRIMARY KEY
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      device_id TEXT NOT NULL,
      public_key BLOB,
      device_info TEXT NOT NULL,   -- JSON string
      device_hash BLOB,
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

def upsert_user(username):
    conn = connect()
    cur = conn.cursor()
    cur.execute("INSERT OR IGNORE INTO users(username) VALUES(?)", (username,))
    conn.commit()
    conn.close()

def register_device(username, device_id, public_key, device_info_dict):
    """Insert/update a device row; returns the stored row as dict."""
    upsert_user(username)
    device_info_json = json.dumps(device_info_dict, separators=(",",":"), sort_keys=True)
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      INSERT OR REPLACE INTO devices(username, device_id, public_key, device_info, device_hash, revoked, registered_at)
      VALUES(?, ?, ?, ?, NULL, 0, ?)
    """, (username, device_id, public_key, device_info_json, now_iso()))
    conn.commit()
    cur.execute("""
      SELECT username, device_id, public_key, device_info, device_hash, revoked, registered_at
      FROM devices
      WHERE username=? AND device_id=?
    """, (username, device_id))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def get_device(username, device_id):
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      SELECT username, device_id, public_key, device_info, device_hash, revoked, registered_at
      FROM devices
      WHERE username=? AND device_id=?
    """, (username, device_id))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def list_devices(username):
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      SELECT device_id, public_key, device_info, device_hash, revoked, registered_at
      FROM devices
      WHERE username=?
      ORDER BY registered_at ASC
    """, (username,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

def revoke_device(username, device_id):
    conn = connect()
    cur = conn.cursor()
    cur.execute("UPDATE devices SET revoked=1 WHERE username=? AND device_id=?", (username, device_id))
    changed = cur.rowcount > 0
    conn.commit()
    conn.close()
    return changed

def create_challenge(challenge_id, username, device_id, challenge_bytes, ttl_seconds=60):
    """Store a short-lived challenge; returns a small record dict."""
    expires = datetime.utcnow() + timedelta(seconds=ttl_seconds)
    conn = connect()
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO challenges(id, username, device_id, challenge, expires_at, consumed)
      VALUES(?, ?, ?, ?, ?, 0)
    """, (challenge_id, username, device_id, challenge_bytes,
          expires.replace(microsecond=0).isoformat() + "Z"))
    conn.commit()
    cur.execute("SELECT id, username, device_id, expires_at FROM challenges WHERE id=?", (challenge_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def mark_challenge_consumed(challenge_id):
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

if __name__ == "__main__":
    init_db()
    print(f"Database ready at: {DB_PATH}")
