# client/local_keystore.py
# Local keystore using AES-256-GCM with a PIN-derived key (scrypt).

import os
import json
import base64
import pathlib
from typing import Dict, Any, Tuple, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

STORE_DIR = pathlib.Path.home() / ".pd_auth"
STORE_DIR.mkdir(exist_ok=True)

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def _b64d(s: str) -> bytes:
    return base64.b64decode(s)

def _derive_key(pin: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a PIN using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(pin.encode())

def encrypt_bytes(plaintext: bytes, pin: str) -> Dict[str, Any]:
    """Encrypt bytes with AES-256-GCM under a key derived from the PIN."""
    salt = os.urandom(16)
    key = _derive_key(pin, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return {
        "kdf": "scrypt",
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ct)
    }

def decrypt_bytes(blob: Dict[str, Any], pin: str) -> bytes:
    """Decrypt a blob produced by encrypt_bytes."""
    salt = _b64d(blob["salt"])
    nonce = _b64d(blob["nonce"])
    ct = _b64d(blob["ciphertext"])
    key = _derive_key(pin, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, ct, None)

def _path_for(username: str, device_id: str) -> pathlib.Path:
    return STORE_DIR / f"{username}-{device_id}.json"

def save_blob(username: str, device_id: str, blob: Dict[str, Any]) -> pathlib.Path:
    """Write the JSON blob to ~/.pd_auth/<username>-<device_id>.json."""
    path = _path_for(username, device_id)
    path.write_text(json.dumps(blob))
    return path

def load_blob(username: str, device_id: str) -> Optional[Dict[str, Any]]:
    """Load the JSON blob if present, else None."""
    path = _path_for(username, device_id)
    if not path.exists():
        return None
    return json.loads(path.read_text())

def save_secret(username: str, device_id: str, pin: str, secret: bytes) -> pathlib.Path:
    """Encrypt and store a secret for (username, device_id)."""
    blob = encrypt_bytes(secret, pin)
    blob["meta"] = {"username": username, "device_id": device_id}
    return save_blob(username, device_id, blob)

def load_secret(username: str, device_id: str, pin: str) -> Tuple[bytes, bytearray]:
    """
    Decrypt the stored secret for (username, device_id).
    Returns (secret_bytes, wipe_buffer). Callers should zeroize wipe_buffer after use.
    """
    blob = load_blob(username, device_id)
    if blob is None:
        raise FileNotFoundError("No keystore file for this user/device.")
    secret = decrypt_bytes(blob, pin)
    return secret, bytearray(secret)

if __name__ == "__main__":
    # Optional quick check:
    u, d, p = "demo", "dev1", "1234"
    s = b"phase2-secret"
    save_secret(u, d, p, s)
    out, buf = load_secret(u, d, p)
    print("decrypted:", out)
    for i in range(len(buf)):
        buf[i] = 0
