#!/usr/bin/env python3
"""
generate_keys.py — Generate RSA keypairs for VPN server and client.

Creates:
  keys/server_private.pem
  keys/server_public.pem
  keys/client_private.pem
  keys/client_public.pem

Run from the repository root:
    python scripts/generate_keys.py
"""

import os
import sys

# Allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.key_manager import (
    generate_rsa_keypair,
    save_private_key,
    save_public_key,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "keys")


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)
    print(f"Generating keys in {KEYS_DIR}/\n")

    # Server keypair
    s_priv, s_pub = generate_rsa_keypair(2048)
    save_private_key(s_priv, os.path.join(KEYS_DIR, "server_private.pem"))
    save_public_key(s_pub, os.path.join(KEYS_DIR, "server_public.pem"))
    print("  [OK] Server keypair: server_private.pem / server_public.pem")

    # Client keypair
    c_priv, c_pub = generate_rsa_keypair(2048)
    save_private_key(c_priv, os.path.join(KEYS_DIR, "client_private.pem"))
    save_public_key(c_pub, os.path.join(KEYS_DIR, "client_public.pem"))
    print("  [OK] Client keypair: client_private.pem / client_public.pem")

    print(f"""
Key distribution:
  Server needs:  server_private.pem  +  client_public.pem
  Client needs:  client_private.pem  +  server_public.pem

  WARNING: Never share private keys.  Only exchange public keys.
""")


if __name__ == "__main__":
    main()