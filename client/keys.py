import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import serialization

# Configuration
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32

def _derive_key(pin: str, salt: bytes) -> bytes:
    """Derives key from PIN using Scrypt (Key Derivation Function)."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(pin.encode('utf-8'))

def encrypt_key_bytes(key_bytes: bytes, pin: str) -> dict:
    """Encrypts raw key bytes (the Ed25519 private key) using AES-256-GCM."""
    salt = os.urandom(16)
    aes_key = _derive_key(pin, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)

    ciphertext = aesgcm.encrypt(nonce, key_bytes, b'')

    return {
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(nonce).decode('utf-8'),
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
    }

def decrypt_key_bytes(encrypted_data: dict, pin: str) -> bytes:
    """Decrypts raw key bytes. Raises InvalidTag on PIN mismatch."""
    try:
        salt = b64decode(encrypted_data['salt'])
        nonce = b64decode(encrypted_data['nonce'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
    except Exception:
        raise ValueError("Invalid encrypted data format.")

    aes_key = _derive_key(pin, salt)
    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(nonce, ciphertext, b'')

def generate_ed25519_keypair():
    """Generates an Ed25519 keypair."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def sign_challenge(private_key_bytes: bytes, challenge: bytes) -> bytes:
    """Signs the server challenge using the Ed25519 private key bytes."""
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(challenge)

def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verifies the signature using the Ed25519 public key bytes."""
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False