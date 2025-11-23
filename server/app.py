import os
import uvicorn
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

# Internal imports
import server.db as db
from keys import verify_signature

# Global in-memory store for challenges
CHALLENGE_STORE: Dict[tuple[str, str], Dict[str, Any]] = {}
EXPIRATION_SECONDS = 300

def set_challenge(username: str, device_id: str, challenge: bytes) -> bytes:
    """Stores a new challenge nonce for a user/device in memory."""
    key = (username, device_id)
    CHALLENGE_STORE[key] = {
        'challenge': challenge,
        'timestamp': time.time()
    }
    return challenge

def get_challenge(username: str, device_id: str, challenge_hex: str) -> bytes | None:
    """Retrieves, validates, and removes the challenge nonce."""
    key = (username, device_id)
    
    if key in CHALLENGE_STORE:
        record = CHALLENGE_STORE[key]
        
        # Check for expiration or challenge mismatch.
        if time.time() - record['timestamp'] > EXPIRATION_SECONDS or record['challenge'].hex() != challenge_hex:
            del CHALLENGE_STORE[key]
            return None

        del CHALLENGE_STORE[key]
        return record['challenge']
        
    return None

# Application Setup
db.initialize_db()
app = FastAPI(title="Passwordless Auth Server (Phase 5)")

# Request Models
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
    """Handles device registration and stores the public key."""
    if db.add_device(request.username, request.device_id, request.public_key_hex):
        return {"status": "success", "message": "Device registered successfully."}
    else:
        raise HTTPException(status_code=400, detail="Device already registered.")

@app.post("/login/challenge")
def login_challenge(request: DeviceInfo):
    """Issues a random challenge (nonce) for the client to sign."""
    device = db.get_device(request.username, request.device_id)
    
    if not device:
        raise HTTPException(status_code=404, detail="User or device not found.")
    
    challenge = os.urandom(32)
    set_challenge(request.username, request.device_id, challenge)
    
    return {
        "status": "success",
        "challenge_hex": challenge.hex(),
        "message": "Challenge issued. Sign it and send it to /login/verify."
    }

@app.post("/login/verify")
def login_verify(request: VerifyRequest):
    """Verifies the client's signature against the stored challenge and public key."""
    device = db.get_device(request.username, request.device_id)

    if not device:
        raise HTTPException(status_code=404, detail="User or device not found.")
    
    stored_challenge = get_challenge(request.username, request.device_id, request.challenge_hex)
    if stored_challenge is None:
        raise HTTPException(status_code=400, detail="Invalid, expired, or reused challenge.")

    try:
        public_key_bytes = bytes.fromhex(device['public_key_hex'])
        signature_bytes = bytes.fromhex(request.signature_hex)
        
        if verify_signature(public_key_bytes, stored_challenge, signature_bytes):
            print(f"[SERVER] SUCCESS: {request.username}/{request.device_id} authenticated.")
            return {"status": "success", "message": "Authentication successful. Access granted."}
        else:
            print(f"[SERVER] FAILURE: Invalid signature for {request.username}/{request.device_id}.")
            raise HTTPException(status_code=401, detail="Authentication failed (Invalid Signature).")

    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid hex formatting in request.")

if __name__ == "__main__":
    print("Run this file using: uvicorn server.app:app --reload")
    print("Ensure you start the server before running client/main.py")