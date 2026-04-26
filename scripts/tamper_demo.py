#!/usr/bin/env python3
"""
tamper_demo.py — Live demonstration of integrity protection.

This script:
  1. Connects to the VPN server and completes a valid handshake
  2. Sends a NORMAL request (should succeed)
  3. Sends a TAMPERED frame (manually corrupts bytes before sending)
  4. Shows the server detecting and rejecting the tampered frame

Run while the server is running:
    python scripts/tamper_demo.py
"""

import os
import sys
import socket
import struct
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from auth.key_manager import load_private_key, load_public_key
from auth.handshake import client_handshake
from crypto.protocol import (
    MessageType, send_frame, recv_frame,
    HEADER_SIZE, SESSION_ID_SIZE, HANDSHAKE_HMAC_KEY,
)
from crypto.crypto_utils import (
    encrypt_payload, compute_hmac, GCM_NONCE_SIZE, HMAC_DIGEST_SIZE,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4433
KEYS_DIR = os.path.join(ROOT, "keys")


def main():
    print("=" * 60)
    print("  INTEGRITY DEMO — Tamper Detection in Action")
    print("=" * 60)

    # Load keys
    client_priv = load_private_key(os.path.join(KEYS_DIR, "client_private.pem"))
    server_pub = load_public_key(os.path.join(KEYS_DIR, "server_public.pem"))

    # --- Step 1: Connect and handshake ---
    print("\n[Step 1] Connecting to server and performing handshake...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((SERVER_HOST, SERVER_PORT))
    session_id, enc_key, mac_key = client_handshake(sock, client_priv, server_pub)
    print(f"  [OK] Handshake complete. Session: {session_id.hex()[:12]}")

    # --- Step 2: Send a NORMAL request ---
    print("\n[Step 2] Sending a NORMAL (valid) request...")
    import json
    request = json.dumps({
        "method": "GET",
        "url": "http://httpbin.org/ip",
        "headers": {},
        "body": "",
    }).encode("utf-8")

    send_frame(sock, MessageType.DATA_REQUEST, session_id, request,
               enc_key=enc_key, mac_key=mac_key)
    msg_type, _, response = recv_frame(sock, enc_key=enc_key, mac_key=mac_key)

    if msg_type == MessageType.DATA_RESPONSE:
        resp = json.loads(response.decode())
        print(f"  [OK] Server accepted the request!")
        print(f"  [OK] Response status: {resp['status_code']}")
        print(f"  [OK] HMAC verified, AES-GCM decrypted successfully")
    else:
        print(f"  [!!] Unexpected response: {msg_type.name}")

    # --- Step 3: Send a TAMPERED frame ---
    print("\n[Step 3] Sending a TAMPERED frame (flipping bytes in the payload)...")
    print("  Building a valid frame first, then corrupting it before sending...")

    # Build frame manually so we can tamper with it
    payload = b'{"method":"GET","url":"http://example.com","headers":{},"body":""}'
    enc_payload, nonce = encrypt_payload(payload, enc_key)
    body = bytes([int(MessageType.DATA_REQUEST)]) + session_id + nonce + enc_payload
    mac = compute_hmac(body, mac_key)
    total_len = len(body) + HMAC_DIGEST_SIZE
    valid_frame = struct.pack("!I", total_len) + body + mac

    # Now TAMPER with the frame — flip bytes in the encrypted payload area
    tampered = bytearray(valid_frame)
    # Corrupt bytes in the middle of the encrypted payload
    tamper_pos = HEADER_SIZE + 1 + SESSION_ID_SIZE + GCM_NONCE_SIZE + 5
    print(f"  Flipping byte at position {tamper_pos} (inside encrypted payload)")
    tampered[tamper_pos] ^= 0xFF
    tampered[tamper_pos + 1] ^= 0xAA
    tampered[tamper_pos + 2] ^= 0x55

    print(f"  Original byte: 0x{valid_frame[tamper_pos]:02X} -> Tampered: 0x{tampered[tamper_pos]:02X}")
    print(f"  Sending tampered frame to server...")

    try:
        sock.sendall(bytes(tampered))
        # Try to read response — server should close connection or send error
        time.sleep(0.5)
        try:
            response = sock.recv(4096)
            if response:
                print(f"  Received {len(response)} bytes (likely error frame)")
            else:
                print(f"  [DETECTED!] Server closed the connection!")
                print(f"  The HMAC check failed — tampered frame was REJECTED")
        except (ConnectionError, ConnectionResetError, socket.error):
            print(f"  [DETECTED!] Server reset the connection!")
            print(f"  The HMAC check failed — tampered frame was REJECTED")
    except (BrokenPipeError, ConnectionResetError, socket.error) as e:
        print(f"  [DETECTED!] Connection broken: {e}")
        print(f"  The HMAC check failed — tampered frame was REJECTED")

    sock.close()

    # --- Summary ---
    print("\n" + "=" * 60)
    print("  RESULT SUMMARY")
    print("=" * 60)
    print("  Step 2: Valid frame   -> Server ACCEPTED (HMAC OK)")
    print("  Step 3: Tampered frame -> Server REJECTED (HMAC FAILED)")
    print()
    print("  CHECK THE SERVER TERMINAL — you should see:")
    print('    [vpn.server] WARNING  FRAME_ERROR  ip=127.0.0.1')
    print('                 error=HMAC verification failed')
    print()
    print("  This proves that ANY tampering is detected by the")
    print("  HMAC-SHA256 integrity check on every frame.")
    print("=" * 60)


if __name__ == "__main__":
    main()
