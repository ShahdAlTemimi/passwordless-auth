import os
import json
import requests
from cryptography.hazmat.primitives import serialization

# Import core crypto functions
try:
    from keys import (
        generate_ed25519_keypair, 
        encrypt_key_bytes, 
        decrypt_key_bytes,
        sign_challenge
    )
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Error: Could not import keys.py or its dependencies. Ensure keys.py is accessible.")
    exit()

# Configuration
SERVER_URL = "http://127.0.0.1:8000"
KEYSTORE_DIR = "./keystore"

def get_user_input(prompt, default_value=None):
    """Helper for command line input."""
    if default_value:
        return input(f"{prompt} [{default_value}]: ") or default_value
    return input(f"{prompt}: ")

def get_keystore_filepath(username: str, device_id: str) -> str:
    """Returns the standardized path for the encrypted key file."""
    return os.path.join(KEYSTORE_DIR, f"{username}-{device_id}.json")

def register_device():
    """Handles keypair generation, local encryption (PIN), and server registration."""
    print("\n--- PHASE 3: DEVICE REGISTRATION ---")
    username = get_user_input("Enter username", "alice")
    device_id = get_user_input("Enter device ID", "laptop")
    pin = get_user_input("Enter local PIN to encrypt private key")

    filepath = get_keystore_filepath(username, device_id)
    if os.path.exists(filepath):
        print(f"[CLIENT] Error: Device {device_id} is already registered locally.")
        return

    private_key, public_key = generate_ed25519_keypair()
    
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    encrypted_data = encrypt_key_bytes(private_key_bytes, pin)

    os.makedirs(KEYSTORE_DIR, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(encrypted_data, f)
        
    print(f"[CLIENT] Private key encrypted and saved locally: {filepath}")

    register_data = {
        "username": username,
        "device_id": device_id,
        "public_key_hex": public_key_bytes.hex()
    }

    try:
        response = requests.post(f"{SERVER_URL}/register", json=register_data)
        response.raise_for_status()
        print(f"[SERVER] Registration successful: {response.json()['message']}")
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to server at {SERVER_URL}. Is server/app.py running?")
    except requests.exceptions.HTTPError as e:
        print(f"[SERVER] Registration failed: {e.response.json().get('detail', 'Unknown error')}")


def login_device():
    """Handles the challenge-response authentication flow."""
    print("\n--- PHASE 5: CHALLENGE-RESPONSE LOGIN ---")
    username = get_user_input("Enter username", "alice")
    device_id = get_user_input("Enter device ID", "laptop")
    
    filepath = get_keystore_filepath(username, device_id)
    if not os.path.exists(filepath):
        print(f"[CLIENT] Error: Keystore file not found at {filepath}. Please Register first.")
        return
        
    # --- Step 1: Request Challenge from Server ---
    print("\n[STEP 1] Requesting challenge...")
    challenge_data = {"username": username, "device_id": device_id}
    challenge_hex = None
    try:
        challenge_response = requests.post(f"{SERVER_URL}/login/challenge", json=challenge_data)
        challenge_response.raise_for_status()
        challenge_payload = challenge_response.json()
        challenge_hex = challenge_payload.get('challenge_hex')
        print(f"[SERVER] Challenge received: {challenge_hex[:16]}...")
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to server at {SERVER_URL}. Is server/app.py running?")
        return
    except requests.exceptions.HTTPError as e:
        print(f"[SERVER] Challenge failed: {e.response.json().get('detail', 'Unknown error')}")
        return
    
    # --- Step 2: Client Side - Decrypt Key & Sign Challenge ---
    
    pin = get_user_input("Enter local PIN to unlock private key")
    
    try:
        with open(filepath, 'r') as f:
            encrypted_data = json.load(f)
        
        private_key_bytes = decrypt_key_bytes(encrypted_data, pin)
        print("[CLIENT] Private key successfully decrypted and unlocked.")
        
    except InvalidTag:
        print("[CLIENT] ERROR: Decryption failed! Incorrect PIN.")
        return
    except Exception as e:
        print(f"[CLIENT] ERROR: Failed to load/decrypt key: {e}")
        return
        
    challenge_bytes = bytes.fromhex(challenge_hex)
    signature_bytes = sign_challenge(private_key_bytes, challenge_bytes)
    signature_hex = signature_bytes.hex()
    print(f"[CLIENT] Challenge signed. Signature: {signature_hex[:16]}...")

    # --- Step 3: Send Signature to Server for Verification ---
    print("\n[STEP 3] Sending signature to server for verification...")
    verify_data = {
        "username": username,
        "device_id": device_id,
        "challenge_hex": challenge_hex,
        "signature_hex": signature_hex
    }
    
    try:
        verify_response = requests.post(f"{SERVER_URL}/login/verify", json=verify_data)
        verify_response.raise_for_status()
        
        print("\n" + "="*50)
        print(f"AUTHENTICATION SUCCESS: {verify_response.json()['message']}")
        print("="*50)

    except requests.exceptions.HTTPError as e:
        detail = e.response.json().get('detail', 'Unknown error')
        print("\n" + "#"*50)
        print(f"AUTHENTICATION FAILED ({e.response.status_code}): {detail}")
        print("#"*50)
    except requests.exceptions.ConnectionError:
        print(f"[ERROR] Could not connect to server at {SERVER_URL}. Is server/app.py running?")
        

def revoke_device():
    """Placeholder for revocation logic (Phase 6)."""
    print("\n--- PHASE 6: REVOCATION ---")
    print("This feature will be fully implemented in the next phase.")


def main():
    """Main application loop and menu."""
    print("Welcome to the Passwordless Authentication Client (Phase 5 Complete).")
    print(f"Server Target: {SERVER_URL}")
    
    while True:
        print("\nChoose an action:")
        print("  1) Register new device (Phase 3)") 
        print("  2) Login from device (Phase 5)")
        print("  3) Revoke a device (Phase 6 - Placeholder)")
        print("  4) Exit")
        
        choice = get_user_input("Enter choice [1-4]")
        
        if choice == '1':
            register_device()
        elif choice == '2':
            login_device()
        elif choice == '3':
            revoke_device()
        elif choice == '4':
            print("Exiting application. Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()