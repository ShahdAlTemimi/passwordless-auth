import argparse
import json
import os
import sys
import httpx

API = "http://127.0.0.1:8000"

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
    # keep the challenge_id locally for the next step
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
        "signature": None  # set in Phase 4
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

def main():
    parser = argparse.ArgumentParser(prog="pd-auth", description="Client for Passwordless Auth (Phase 1)")
    sub = parser.add_subparsers(dest="cmd", required=True)

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

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
