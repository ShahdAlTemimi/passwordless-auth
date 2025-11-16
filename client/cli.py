# client/cli.py
import argparse
import json
import os
import sys
import httpx

from local_keystore import save_secret, load_secret  # Phase 2 keystore

API = "http://127.0.0.1:8000"

# -------- Server commands (Phase 1) --------

def cmd_register(a):
    payload = {
        "username": a.username,
        "device_id": a.device_id,
        "device_info": {"platform": a.platform, "model": a.model},
        "public_key": None
    }
    r = httpx.post(f"{API}/register", json=payload, timeout=10.0)
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))

def cmd_login_start(a):
    payload = {"username": a.username, "device_id": a.device_id}
    r = httpx.post(f"{API}/login/challenge", json=payload, timeout=10.0)
    r.raise_for_status()
    data = r.json()
    print(json.dumps(data, indent=2))
    with open(".last_challenge.json", "w") as f:
        json.dump({
            "username": a.username,
            "device_id": a.device_id,
            "challenge_id": data["challenge_id"]
        }, f)

def cmd_login_complete(_a):
    if not os.path.exists(".last_challenge.json"):
        print("Run login-start first.", file=sys.stderr)
        sys.exit(1)
    with open(".last_challenge.json") as f:
        ch = json.load(f)
    payload = {
        "username": ch["username"],
        "device_id": ch["device_id"],
        "challenge_id": ch["challenge_id"],
        "signature": None
    }
    r = httpx.post(f"{API}/login/response", json=payload, timeout=10.0)
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))

def cmd_devices(a):
    r = httpx.get(f"{API}/devices", params={"username": a.username}, timeout=10.0)
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))

def cmd_revoke(a):
    payload = {"username": a.username, "device_id": a.device_id}
    r = httpx.post(f"{API}/devices/revoke", json=payload, timeout=10.0)
    r.raise_for_status()
    print(json.dumps(r.json(), indent=2))

# -------- Keystore commands (Phase 2) --------

def cmd_ks_save(a):
    secret = a.secret.encode()
    path = save_secret(a.username, a.device_id, a.pin, secret)
    print(f"saved: {path}")

def cmd_ks_load(a):
    secret, buf = load_secret(a.username, a.device_id, a.pin)
    try:
        # demo output; in real use, avoid printing secrets
        print("secret (utf-8):", secret.decode(errors="replace"))
        print("secret (hex):", secret.hex())
    finally:
        for i in range(len(buf)):
            buf[i] = 0  # zeroize

def main():
    parser = argparse.ArgumentParser(prog="pd-auth", description="Client for Passwordless Auth")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # Server
    r = sub.add_parser("register", help="register a new device")
    r.add_argument("--username", required=True)
    r.add_argument("--device-id", required=True)
    r.add_argument("--platform", default="unknown")
    r.add_argument("--model", default="unknown")
    r.set_defaults(func=cmd_register)

    s = sub.add_parser("login-start", help="begin login and get a challenge")
    s.add_argument("--username", required=True)
    s.add_argument("--device-id", required=True)
    s.set_defaults(func=cmd_login_start)

    c = sub.add_parser("login-complete", help="complete login using saved challenge")
    c.set_defaults(func=cmd_login_complete)

    d = sub.add_parser("devices", help="list all devices for a user")
    d.add_argument("--username", required=True)
    d.set_defaults(func=cmd_devices)

    rv = sub.add_parser("revoke", help="revoke a specific device")
    rv.add_argument("--username", required=True)
    rv.add_argument("--device-id", required=True)
    rv.set_defaults(func=cmd_revoke)

    # Keystore
    ks = sub.add_parser("ks-save", help="encrypt+store a secret with a PIN")
    ks.add_argument("--username", required=True)
    ks.add_argument("--device-id", required=True)
    ks.add_argument("--pin", required=True)
    ks.add_argument("--secret", required=True, help="text to store (e.g., 'hello')")
    ks.set_defaults(func=cmd_ks_save)

    kl = sub.add_parser("ks-load", help="decrypt and show the secret (demo)")
    kl.add_argument("--username", required=True)
    kl.add_argument("--device-id", required=True)
    kl.add_argument("--pin", required=True)
    kl.set_defaults(func=cmd_ks_load)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
