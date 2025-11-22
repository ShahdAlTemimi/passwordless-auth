# client/main.py
#
# Interactive wizard client for Project D — Passwordless Auth (Phases 1-4).
# Talks to the FastAPI server and uses the local keystore + Ed25519 keys.

import json
import sys
import base64
import httpx
import getpass
from typing import Optional

from local_keystore import save_secret, load_secret, load_blob, save_blob
from keys import generate_and_store_keypair, sign_bytes, derive_public_key_b64_from_store
from local_keystore import STORE_DIR

API = "http://127.0.0.1:8000"


# ------------- Helpers -------------

def ask(prompt: str, default: str | None = None) -> str:
    """Simple input helper with optional default."""
    if default is None:
        return input(prompt).strip()
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def ask_pin(prompt_text: str = "Enter PIN: ") -> str:
    """Use getpass so PIN is not shown on screen."""
    return getpass.getpass(prompt_text).strip()


def print_header(title: str) -> None:
    print("\n" + "=" * 40)
    print(" ", title)
    print("=" * 40 + "\n")


def pretty_print(obj) -> None:
    """Print JSON or text nicely."""
    if isinstance(obj, (dict, list)):
        print(json.dumps(obj, indent=2))
    else:
        print(obj)


def api_post(path: str, json_body: dict):
    """Wrapper around POST with basic error handling."""
    url = f"{API}{path}"
    try:
        r = httpx.post(url, json=json_body)
        r.raise_for_status() # Raise an exception for 4xx or 5xx status codes
        return r.json()
    except httpx.HTTPStatusError as e:
        print(f"[!] API Error: {e.response.status_code} {e.response.reason_phrase}")
        try:
            error_detail = e.response.json().get("detail")
            if error_detail:
                print(f"[!] Detail: {error_detail}")
        except:
            pass
        return None
    except httpx.RequestError as e:
        print(f"[!] An error occurred while requesting {e.request.url!r}: {e}")
        print("[!] Is the FastAPI server running?")
        return None


# ------------- Actions -------------

def action_register():
    """Phase 3: Generate keypair, store private key locally, send public key to server."""
    print_header("1) Register New Device (Phase 3)")
    username = ask("Enter username (e.g., sara.c)")
    device_id = ask("Enter device ID (e.g., work_laptop)")
    pin = ask_pin("Choose a PIN (used for local key encryption): ")

    device_info = {
        "os": sys.platform,
        "client": "python-cli",
        "key_type": "Ed25519",
    }

    try:
        # Phase 3: Generate keypair, store private key, get public key
        public_key_b64 = generate_and_store_keypair(username, device_id, pin)
        print(f"[+] Keypair generated and private key securely stored locally.")
        print(f"[+] Public Key (b64): {public_key_b64[:10]}...{public_key_b64[-10:]}")
    except Exception as e:
        print(f"[!] Failed to generate/store keypair: {e}")
        return

    # Phase 3: Send public key to server for registration
    body = {
        "username": username,
        "device_id": device_id,
        "device_info": device_info,
        "public_key": public_key_b64,
    }

    result = api_post("/register", body)

    if result:
        print("\n[+] Registration Successful! Server Response:")
        pretty_print(result)


def action_login():
    """Phase 4: Challenge-Response login with signature."""
    print_header("2) Login (Phase 4: Challenge-Response)")
    username = ask("Enter username (e.g., sara.c)")
    device_id = ask("Enter device ID (e.g., work_laptop)")
    pin = ask_pin("Enter your PIN to unlock the private key: ")

    # 1. Get Challenge
    print("\n-- 1. Requesting Challenge --")
    challenge_body = {"username": username, "device_id": device_id}
    challenge_result = api_post("/login/challenge", challenge_body)

    if not challenge_result:
        return

    challenge_b64 = challenge_result["challenge"]
    challenge_id = challenge_result["challenge_id"]

    print(f"[+] Challenge received (ID: {challenge_id[:8]}...): {challenge_b64[:10]}...")

    # 2. Sign Challenge (Client-side Cryptography)
    try:
        # Decode the base64 challenge back to raw bytes
        challenge_bytes = base64.b64decode(challenge_b64)

        # Phase 4: Sign the challenge bytes with the locally stored private key
        signature_bytes = sign_bytes(username, device_id, pin, challenge_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode()

        print(f"[+] Challenge signed successfully using private key.")
        print(f"[+] Signature (b64): {signature_b64[:10]}...{signature_b64[-10:]}")

    except FileNotFoundError:
        print("[!] Error: No private key found. Did you forget to register (Option 1)?")
        return
    except Exception as e:
        print(f"[!] Error signing challenge (wrong PIN?): {e}")
        return

    # 3. Send Response (Challenge ID + Signature)
    print("\n-- 3. Sending Response --")
    response_body = {
        "username": username,
        "device_id": device_id,
        "challenge_id": challenge_id,
        "signature": signature_b64,  # Phase 4 requirement
    }

    session_result = api_post("/login/response", response_body)

    if session_result:
        print("\n[+] Login SUCCESSFUL! Session Granted.")
        pretty_print(session_result)


def action_list_devices():
    """List devices for a user (Phase 6/partial)."""
    print_header("3) List Registered Devices")
    username = ask("Enter username (e.g., sara.c)")

    result = api_post(f"/devices?username={username}", {})

    if result is not None:
        print("\n[+] Device List:")
        pretty_print(result)


def action_revoke():
    """Revoke a device (Phase 6/partial)."""
    print_header("4) Revoke a Device")
    username = ask("Enter username (e.g., sara.c)")
    device_id = ask("Enter device ID to revoke (e.g., old_phone)")

    body = {"username": username, "device_id": device_id}
    result = api_post("/devices/revoke", body)

    if result:
        print("\n[+] Revocation Successful! Server Response:")
        pretty_print(result)


def action_keystore_test():
    """Phase 2: Test the local keystore functions."""
    print_header("5) Keystore Test (Phase 2)")
    username = ask("Enter test username", "test_user")
    device_id = ask("Enter test device ID", "test_device")
    pin = ask_pin("Choose a test PIN: ")
    secret_text = ask("Enter a secret to store", "My Super Secret Text!")

    secret_bytes = secret_text.encode("utf-8")

    try:
        path = save_secret(username, device_id, pin, secret_bytes)
        print(f"\n[+] Secret saved to file: {path.name} in {STORE_DIR}")
    except Exception as e:
        print(f"[!] Failed to save secret: {e}")
        return

    try:
        secret, buf = load_secret(username, device_id, pin)
    except FileNotFoundError:
        print("[!] Keystore file was not found during load.")
        return
    except Exception as e:
        print(f"[!] Failed to load secret (Wrong PIN?): {e}")
        return

    try:
        # Check if the decrypted secret matches the original
        if secret == secret_bytes:
            print("\n[+] Decryption Successful!")
            print("Decrypted secret (utf-8):", secret.decode("utf-8", errors="replace"))
        else:
            print("[!] Decryption Failed: Retrieved secret does not match original.")

    finally:
        # zeroize buffer
        for i in range(len(buf)):
            buf[i] = 0


# ------------- Main loop -------------

def main():
    print("====================================")
    print("  Project D — Passwordless Auth")

    print("====================================\n")

    while True:
        print("Choose an action:")
        print("  1) Register new device (with keypair)")
        print("  2) Login from device (challenge–response)")
        print("  3) List devices for a user (Phase 6/partial)")
        print("  4) Revoke a device (Phase 6/partial)")
        print("  5) Keystore test (Phase 2)")
        print("  6) Exit")

        choice = ask("Enter choice [1-6]: ")

        if choice == "1":
            action_register()
        elif choice == "2":
            action_login()
        elif choice == "3":
            action_list_devices()
        elif choice == "4":
            action_revoke()
        elif choice == "5":
            action_keystore_test()
        elif choice == "6":
            print("\nExiting.")
            sys.exit(0)
        else:
            print("\nInvalid choice. Please enter a number from 1 to 6.")

if __name__ == "__main__":
    main()