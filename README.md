# Project D — Passwordless Authentication (Phase 1)

Basic client–server scaffold using **FastAPI** and **SQLite**.

### ✅ Features
- Register devices (no crypto yet)
- Challenge–response flow (dummy)
- Session creation
- Device listing and revocation

---

## ⚙️ Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn server.app:app --reload  # start server
```

Open another terminal in the same folder (venv active) for the client.

---

## 💻 CLI Commands

Run from inside `passwordless-auth/`:

```bash
# Register a device
python client/cli.py register --username sara --device-id laptop-uuid --platform darwin --model macbook

# Start login (get challenge)
python client/cli.py login-start --username sara --device-id laptop-uuid

# Complete login
python client/cli.py login-complete

# List devices
python client/cli.py devices --username sara

# Revoke a device
python client/cli.py revoke --username sara --device-id laptop-uuid
```

---

## 🧪 Test with curl (optional)

```bash
# Register
curl -s -X POST http://127.0.0.1:8000/register \
  -H 'content-type: application/json' \
  -d '{"username":"sara","device_id":"laptop-uuid","device_info":{"platform":"darwin","model":"macbook"}}' | jq

# Challenge
curl -s -X POST http://127.0.0.1:8000/login/challenge \
  -H 'content-type: application/json' \
  -d '{"username":"sara","device_id":"laptop-uuid"}' | jq
```

Copy the `challenge_id` and continue:
```bash
CHID=<paste_id_here>
curl -s -X POST http://127.0.0.1:8000/login/response \
  -H 'content-type: application/json' \
  -d "{\"username\":\"sara\",\"device_id\":\"laptop-uuid\",\"challenge_id\":\"$CHID\",\"signature\":null}" | jq
```

---

## 🧰 Database
A file `pd_auth.db` is created in the `server/` folder.  
Reset with:
```bash
rm server/pd_auth.db
```

---

