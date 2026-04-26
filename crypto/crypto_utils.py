"""
crypto_utils.py — Cryptographic primitives for the VPN tunnel.

Provides:
  - AES-256-GCM authenticated encryption / decryption
  - HMAC-SHA256 computation and constant-time verification
  - HKDF-based key derivation (master secret → encryption key + MAC key)
  - Secure random key generation

All functions raise on failure (tampered ciphertext, bad HMAC, etc.) so
callers can catch and log / reject cleanly.
"""

import os
import hmac as _hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_KEY_SIZE = 32        # 256 bits
GCM_NONCE_SIZE = 12      # 96 bits — recommended for AES-GCM
HMAC_KEY_SIZE = 32       # 256 bits
HMAC_DIGEST_SIZE = 32    # SHA-256


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------
def generate_session_key() -> bytes:
    """Return a cryptographically random 256-bit key suitable for AES-256."""
    return os.urandom(AES_KEY_SIZE)


# ---------------------------------------------------------------------------
# AES-256-GCM encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt_payload(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    Returns:
        (ciphertext_with_tag, nonce)
        The ciphertext already contains the 16-byte GCM auth tag appended.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")

    nonce = os.urandom(GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # no AAD needed here
    return ciphertext, nonce


def decrypt_payload(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Decrypt *ciphertext* produced by :func:`encrypt_payload`.

    Raises ``cryptography.exceptions.InvalidTag`` if the ciphertext or tag
    has been tampered with.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError(f"Nonce must be {GCM_NONCE_SIZE} bytes, got {len(nonce)}")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# HMAC-SHA256  (used on *frames*, covering header + encrypted payload)
# ---------------------------------------------------------------------------
def compute_hmac(data: bytes, key: bytes) -> bytes:
    """Compute HMAC-SHA256 over *data* using *key*.  Returns 32-byte digest."""
    return _hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(data: bytes, mac: bytes, key: bytes) -> bool:
    """Constant-time comparison of expected HMAC vs *mac*.

    Returns True if valid, False otherwise.
    """
    expected = compute_hmac(data, key)
    return _hmac.compare_digest(expected, mac)


# ---------------------------------------------------------------------------
# Key derivation (HKDF — RFC 5869)
# ---------------------------------------------------------------------------
def derive_keys(
    master_secret: bytes,
    salt: bytes | None = None,
    info: bytes = b"vpn-tunnel-keys",
) -> tuple[bytes, bytes]:
    """Derive an encryption key and a MAC key from *master_secret*.

    Uses HKDF-SHA256 to produce 64 bytes, split into:
      - enc_key  (first 32 bytes)  → used for AES-256-GCM
      - mac_key  (last 32 bytes)   → used for frame HMAC

    If *salt* is None a zero-filled salt of hash-length is used (per RFC 5869).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE + HMAC_KEY_SIZE,
        salt=salt,
        info=info,
    )
    derived = hkdf.derive(master_secret)
    enc_key = derived[:AES_KEY_SIZE]
    mac_key = derived[AES_KEY_SIZE:]
    return enc_key, mac_key
