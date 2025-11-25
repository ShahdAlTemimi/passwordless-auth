# Project D — Passwordless Authentication (Short README)

A minimal passwordless authentication system using:
- Ed25519 keypairs
- AES‑256‑GCM keystore protected by PIN (scrypt)
- Challenge–response login with digital signatures
- Device integrity hashing (SHA‑256)
- Multi‑device support + revocation
- FastAPI server + Python interactive client

## Setup
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

## Run Server
uvicorn server.app:app --reload

## Run Client
python client/main.py

## Main Features
- Register device → generates keypair + stores public key on server
- Login → server challenge, client signature, server verification
- List devices → shows all registered devices + revoked status
- Revoke device → blocks future logins from that device
