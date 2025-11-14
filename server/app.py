from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
import base64, os, uuid
from datetime import datetime

# Import DB helpers from server/db.py
from . import db

app = FastAPI(title="Project D — Passwordless Auth (Phase 1)")

# Request/response models
class RegisterIn(BaseModel):
    username: str
    device_id: str
    device_info: Dict[str, Any]
    public_key: Optional[str] = None  # placeholder for later phases

class RegisterOut(BaseModel):
    device_hash: Optional[str] = None
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
    signature: Optional[str] = None  # real signature in Phase 4

class SessionOut(BaseModel):
    session_id: str
    issued_at: str
    ttl: int

class RevokeIn(BaseModel):
    username: str
    device_id: str
    reason: Optional[str] = None

@app.on_event("startup")
def startup():
    db.init_db()

@app.post("/register", response_model=RegisterOut, status_code=201)
def register(body: RegisterIn):
    if not body.username or not body.device_id:
        raise HTTPException(status_code=400, detail="username and device_id required")
    pk_bytes = base64.b64decode(body.public_key) if body.public_key else None
    row = db.register_device(body.username, body.device_id, pk_bytes, body.device_info)
    if not row:
        raise HTTPException(status_code=500, detail="could not register device")
    return RegisterOut(device_hash=row.get("device_hash"), registered_at=row["registered_at"])

@app.post("/login/challenge", response_model=ChallengeOut)
def login_challenge(body: ChallengeIn):
    dev = db.get_device(body.username, body.device_id)
    if not dev:
        raise HTTPException(status_code=404, detail="device not found")
    if dev["revoked"]:
        raise HTTPException(status_code=403, detail="device revoked")

    challenge_id = str(uuid.uuid4())
    challenge_bytes = os.urandom(32)  # 32-byte random nonce
    rec = db.create_challenge(challenge_id, body.username, body.device_id, challenge_bytes, ttl_seconds=60)
    if not rec:
        raise HTTPException(status_code=500, detail="could not create challenge")

    return ChallengeOut(
        challenge_id=rec["id"],
        challenge=base64.b64encode(challenge_bytes).decode(),
        expires_in=60
    )

@app.post("/login/response", response_model=SessionOut)
def login_response(body: ResponseIn):
    # Phase 1: accept if challenge exists, not expired, not consumed (no signature check yet)
    conn = db.connect(); cur = conn.cursor()
    cur.execute("SELECT id, username, device_id, expires_at, consumed FROM challenges WHERE id=?", (body.challenge_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=400, detail="invalid challenge_id")
    if row["username"] != body.username or row["device_id"] != body.device_id:
        raise HTTPException(status_code=400, detail="challenge does not match user/device")
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", ""))
    if datetime.utcnow() > expires_at:
        raise HTTPException(status_code=400, detail="challenge expired")
    if row["consumed"]:
        raise HTTPException(status_code=400, detail="challenge already used")

    dev = db.get_device(body.username, body.device_id)
    if not dev or dev["revoked"]:
        raise HTTPException(status_code=403, detail="device invalid or revoked")

    db.mark_challenge_consumed(body.challenge_id)
    session_id = str(uuid.uuid4())
    sess = db.create_session(session_id, body.username, body.device_id, ttl_seconds=3600)
    return SessionOut(session_id=sess["id"], issued_at=sess["issued_at"], ttl=3600)

@app.get("/devices")
def list_devices(username: str):
    return db.list_devices(username)

@app.post("/devices/revoke")
def revoke(body: RevokeIn):
    ok = db.revoke_device(body.username, body.device_id)
    if not ok:
        raise HTTPException(status_code=404, detail="device not found")
    return {"revoked": True}
