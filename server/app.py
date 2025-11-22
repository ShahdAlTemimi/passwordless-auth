from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import base64, os, uuid
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import db  # DB helpers in server/db.py

# The server title should reflect the completed phases
app = FastAPI(title="Project D — Passwordless Auth (Phases 1–4)")

# ---------- Pydantic models ----------

class RegisterIn(BaseModel):
    username: str
    device_id: str
    device_info: Dict[str, Any]
    public_key: Optional[str] = None  # base64 Ed25519 in Phase 3

class RegisterOut(BaseModel):
    registered_at: str

class ChallengeIn(BaseModel):
    username: str
    device_id: str

class ChallengeOut(BaseModel):
    challenge_id: str
    challenge: str  # base64
    expires_in: int

class ResponseIn(BaseModel):
    username: str
    device_id: str
    challenge_id: str
    signature: Optional[str] = None  # base64 Ed25519 signature in Phase 4

class SessionOut(BaseModel):
    session_id: str
    issued_at: str
    ttl: int

class RevokeIn(BaseModel):
    username: str
    device_id: str
    reason: Optional[str] = None


# ---------- Startup ----------

@app.on_event("startup")
def startup():
    """Initializes the database on server start."""
    # Already called inside db.py, but good to ensure
    db.init_db()


# ---------- Device Management (Phase 1, 3, 6/partial) ----------

@app.post("/register", response_model=RegisterOut)
def register(body: RegisterIn):
    """
    Phase 3: Stores the device's public key for challenge-response.
    Phase 5 (device_hash) logic is skipped.
    """
    pk_bytes = None
    if body.public_key:
        try:
            # Decode the base64 public key
            pk_bytes = base64.b64decode(body.public_key)
            # Optional: ensure it's a valid Ed25519 key (32 bytes)
            if len(pk_bytes) != 32:
                 raise ValueError("Public key must be 32 bytes.")
        except Exception:
            raise HTTPException(status_code=400, detail="invalid public key encoding or format")

    # Register the device with the public key
    device = db.register_device(
        body.username,
        body.device_id,
        body.device_info,
        public_key_bytes=pk_bytes
    )

    if device is None:
        raise HTTPException(status_code=500, detail="Failed to register device")

    return RegisterOut(
        registered_at=device["registered_at"],
    )


# ---------- Login Flow (Phase 1, 3, 4) ----------

@app.post("/login/challenge", response_model=ChallengeOut)
def challenge(body: ChallengeIn):
    """
    Phase 3: Issues a random challenge only if the device has a public key.
    """
    device = db.get_device_by_id(body.username, body.device_id)

    if device is None or device["revoked"]:
        raise HTTPException(status_code=403, detail="device not registered or revoked")

    pk_bytes = device["public_key"]

    if pk_bytes is None:
        # Deny challenge if no public key is stored (Phase 3 requirement)
        raise HTTPException(status_code=403, detail="device must register a public key first")

    # TTL of challenge (60 seconds)
    TTL_SECONDS = 60
    challenge_id = str(uuid.uuid4())
    challenge_obj = db.create_challenge(
        challenge_id, body.username, body.device_id, ttl_seconds=TTL_SECONDS
    )

    # challenge is stored as raw bytes, encode it to base64 for the client
    challenge_b64 = base64.b64encode(challenge_obj["challenge"]).decode()

    return ChallengeOut(
        challenge_id=challenge_id,
        challenge=challenge_b64,
        expires_in=TTL_SECONDS,
    )


@app.post("/login/response", response_model=SessionOut)
def response(body: ResponseIn):
    """
    Phase 4: Verifies the signature of the challenge using the stored public key.
    """
    # ---------- Phase 1: challenge retrieval and expiry check ----------
    challenge_data = db.get_challenge(body.challenge_id)

    if challenge_data is None:
        raise HTTPException(status_code=404, detail="challenge not found")
    if challenge_data["consumed"]:
        raise HTTPException(status_code=403, detail="challenge already consumed")

    now = datetime.utcnow()
    expires_at = datetime.fromisoformat(challenge_data["expires_at"].replace("Z", "+00:00"))
    if now > expires_at:
        db.mark_challenge_consumed(body.challenge_id) # Consume expired challenge
        raise HTTPException(status_code=403, detail="challenge expired")

    challenge_bytes = challenge_data["challenge"] # Raw bytes of the challenge

    # ---------- Phase 3: public key retrieval and device check ----------
    device = db.get_device_by_id(body.username, body.device_id)

    if device is None or device["revoked"]:
        raise HTTPException(status_code=403, detail="device not registered or revoked")

    # Security check: Does the challenge belong to the device specified in the response?
    if (challenge_data["username"] != body.username or
            challenge_data["device_id"] != body.device_id):
        raise HTTPException(
            status_code=400,
            detail="challenge/public key / info mismatch",
        )

    pk_bytes = device["public_key"]

    # ---------- Phase 4: signature verification ----------
    if pk_bytes is not None:
        if not body.signature:
            raise HTTPException(
                status_code=400,
                detail="signature required for this device",
            )
        try:
            signature_bytes = base64.b64decode(body.signature)
        except Exception:
            raise HTTPException(status_code=400, detail="invalid signature encoding")

        try:
            # Reconstruct the public key and verify the signature
            pub = Ed25519PublicKey.from_public_bytes(pk_bytes)
            pub.verify(signature_bytes, challenge_bytes)
        except Exception:
            # Signature verification failed (critical failure)
            raise HTTPException(status_code=403, detail="invalid signature")

    else:
        # A device *must* have a public key to attempt challenge-response (Phase 3)
        raise HTTPException(status_code=403, detail="device does not support challenge-response login")


    # All checks passed. Consume the challenge and create a session.
    db.mark_challenge_consumed(body.challenge_id)
    session_id = str(uuid.uuid4())
    sess = db.create_session(session_id, body.username, body.device_id, ttl_seconds=3600)
    return SessionOut(session_id=sess["id"], issued_at=sess["issued_at"], ttl=3600)


