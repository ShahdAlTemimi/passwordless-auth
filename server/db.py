import sqlite3
import hashlib
import os

DATABASE_NAME = "passwordless.db"

def initialize_db():
    """Initializes the SQLite database and creates the 'devices' table."""
    conn = None
    try:
        # Check if DB file exists before connection
        is_new_db = not os.path.exists(DATABASE_NAME)
        
        conn = sqlite3.connect(DATABASE_NAME)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                username TEXT NOT NULL,
                device_id TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                device_hash TEXT,
                revoked INTEGER DEFAULT 0,
                PRIMARY KEY (username, device_id)
            )
        """)
        conn.commit()
        
        if is_new_db:
            print(f"[DB INIT] Created new database: {DATABASE_NAME}")
        else:
            print(f"[DB INIT] Connected to existing database: {DATABASE_NAME}")
            
    except sqlite3.Error as e:
        print(f"[DB ERROR] Failed to initialize database: {e}")
    finally:
        if conn:
            conn.close()

def compute_device_hash(username, device_id, public_key_hex):
    """Compute a SHA-256 hash over canonical device fields."""
    msg = f"{username}|{device_id}|{public_key_hex}"
    return hashlib.sha256(msg.encode()).hexdigest()

def add_device(username: str, device_id: str, public_key_hex: str) -> bool:
    """Adds a new device and public key to the database (also stores device_hash)."""
    device_hash = compute_device_hash(username, device_id, public_key_hex)

    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO devices (username, device_id, public_key_hex, device_hash) VALUES (?, ?, ?, ?)",
            (username, device_id, public_key_hex, device_hash)
        )
        conn.commit()
        print(f"[DB] Added device {username}/{device_id}")
        return True
    except sqlite3.IntegrityError:
        print(f"[DB] Add failed — device exists: {username}/{device_id}")
        return False
    finally:
        conn.close()

def get_device(username: str, device_id: str):
    """Retrieves device details (public key, revoked status, device_hash) from the database."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT public_key_hex, revoked, device_hash FROM devices WHERE username = ? AND device_id = ?",
        (username, device_id)
    )
    result = cursor.fetchone()
    conn.close()
    if result:
        return {"public_key_hex": result[0], "revoked": result[1], "device_hash": result[2]}
    return None

def revoke_device(username: str, device_id: str) -> bool:
    """Marks a device as revoked in the database."""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE devices SET revoked = 1 WHERE username = ? AND device_id = ?",
        (username, device_id)
    )
    conn.commit()
    rowcount = cursor.rowcount
    conn.close()
    print(f"[DB] Revoked {username}/{device_id}")
    return rowcount > 0

if __name__ == "__main__":
    # Small manual init helper (student proof-of-run)
    print("[DB] Initializing database...")
    initialize_db()
    print("[DB] Done.")