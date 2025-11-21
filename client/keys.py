# client/keys.py
# Ed25519 key generation + loading via the local keystore (Phase 3).

import base64
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)

from local_keystore import save_secret, load_secret  # uses AES-256-GCM (Phase 2)

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()

def generate_and_store_keypair(username: str, device_id: str, pin: str) -> str:
    """
    Generate an Ed25519 keypair. Store the private key (raw 32 bytes) in the keystore.
    Returns the base64-encoded public key string.
    """
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    # Save encrypted with the user's PIN
    save_secret(username, device_id, pin, priv_raw)

    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64e(pub_raw)

def load_private_key(username: str, device_id: str, pin: str) -> Ed25519PrivateKey:
    """
    Load and decrypt the private key from the keystore using the PIN.
    """
    priv_raw, wipe_buf = load_secret(username, device_id, pin)
    try:
        priv = Ed25519PrivateKey.from_private_bytes(bytes(priv_raw))
    finally:
        # zeroize the temporary buffer copy
        for i in range(len(wipe_buf)):
            wipe_buf[i] = 0
    return priv

def derive_public_key_b64_from_store(username: str, device_id: str, pin: str) -> str:
    """
    Decrypt the private key and return the base64 public key derived from it.
    """
    priv = load_private_key(username, device_id, pin)
    pub = priv.public_key()
    pub_raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _b64e(pub_raw)

def sign_bytes(username: str, device_id: str, pin: str, message: bytes) -> bytes:
    """
    Convenience signer (will be used in Phase 4).
    """
    priv = load_private_key(username, device_id, pin)
    return priv.sign(message)

def verify_signature(pubkey_b64: str, message: bytes, signature: bytes) -> bool:
    """
    Verify a signature with a base64-encoded Ed25519 public key.
    (Useful for local tests.)
    """
    pub_raw = base64.b64decode(pubkey_b64)
    pub = Ed25519PublicKey.from_public_bytes(pub_raw)
    try:
        pub.verify(signature, message)
        return True
    except Exception:
        return False
