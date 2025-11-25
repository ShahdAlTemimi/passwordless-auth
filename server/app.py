import os
import time
import hmac
import hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from . import db  
from keys import verify_signature  

CHALLENGE_STORE = {}
EXPIRATION_SECONDS = 300

def get_challenge_key(username, device_id):
    return f"{username}:{device_id}"

def set_challenge(username, device_id, challenge):
    key = get_challenge_key(username, device_id)
    CHALLENGE_STORE[key] = {'challenge': challenge, 'timestamp': time.time()}
    print(f"[CHALLENGE] stored for {username}/{device_id}: {challenge.hex()[:12]}...")
    return challenge

def get_challenge(username, device_id, challenge_hex):
    key = get_challenge_key(username, device_id)
    record = CHALLENGE_STORE.get(key)
    if not record:
        return None
    # expiration
    if time.time() - record['timestamp'] > EXPIRATION_SECONDS:
        del CHALLENGE_STORE[key]
        return None
    # constant-time compare
    if not hmac.compare_digest(record['challenge'].hex(), challenge_hex):
        del CHALLENGE_STORE[key]
        return None
    del CHALLENGE_STORE[key]
    return record['challenge']

# App setup
db.initialize_db()
app = FastAPI(title="Passwordless Auth Server (Phase 5+)")

class DeviceInfo(BaseModel):
    username: str
    device_id: str

class RegisterRequest(DeviceInfo):
    public_key_hex: str

class VerifyRequest(DeviceInfo):
    challenge_hex: str
    signature_hex: str

@app.post("/register")
def register(request: RegisterRequest):
    """Register device and save device_hash (Phase 5)."""
    ok = db.add_device(request.username, request.device_id, request.public_key_hex)
    if ok:
        return {"status": "success", "message": "Device registered successfully."}
    raise HTTPException(status_code=400, detail="Device already registered.")

@app.post("/login/challenge")
def login_challenge(request: DeviceInfo):
    device = db.get_device(request.username, request.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="User or device not found.")
    if device.get("revoked") == 1:
        raise HTTPException(status_code=403, detail="Device has been revoked and cannot log in.")
    challenge = os.urandom(32)
    set_challenge(request.username, request.device_id, challenge)
    return {"status": "success", "challenge_hex": challenge.hex(), "message": "Challenge issued."}

@app.post("/login/verify")
def login_verify(request: VerifyRequest):
    """Verify device integrity (Phase 5) then validate signature (Phase 4)."""
    device = db.get_device(request.username, request.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="User or device not found.")

    # Revocation check
    if device.get("revoked") == 1:
        raise HTTPException(status_code=403, detail="Device is revoked.")

    # === Minimal Phase 5 integrity check ===
    stored_hash = device.get("device_hash")
    if stored_hash:
        expected = hashlib.sha256(f"{request.username}|{request.device_id}|{device['public_key_hex']}".encode()).hexdigest()
        if expected != stored_hash:
            # Log details for demo (crop these lines in your screenshot)
            print("[ALERT] Integrity Mismatch!")
            print(f"Stored:   {stored_hash[:20]}...")
            print(f"Computed: {expected[:20]}...")
            raise HTTPException(status_code=403, detail="Device integrity check failed.")

    # === End integrity check ===

    # Validate challenge
    stored_challenge = get_challenge(request.username, request.device_id, request.challenge_hex)
    if stored_challenge is None:
        raise HTTPException(status_code=400, detail="Invalid, expired, or reused challenge.")

    # Verify signature
    try:
        public_key_bytes = bytes.fromhex(device['public_key_hex'])
        signature_bytes = bytes.fromhex(request.signature_hex)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex formatting in request.")

    if verify_signature(public_key_bytes, stored_challenge, signature_bytes):
        print(f"[SERVER] SUCCESS: {request.username}/{request.device_id} authenticated.")
        return {"status": "success", "message": "Authentication successful. Access granted."}
    else:
        print(f"[SERVER] FAILURE: Invalid signature for {request.username}/{request.device_id}.")
        raise HTTPException(status_code=401, detail="Authentication failed (Invalid Signature).")

@app.post("/revoke")
def revoke(request: DeviceInfo):
    ok = db.revoke_device(request.username, request.device_id)
    if ok:
        return {"status": "success", "message": f"Device {request.device_id} revoked."}
    raise HTTPException(status_code=404, detail="User or device not found.")