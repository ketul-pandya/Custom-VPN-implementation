"""
key_manager.py — RSA key generation, storage, and loading.

Key conventions:
  - Private keys are stored in PEM format (optionally encrypted).
  - Public keys are stored in PEM (SubjectPublicKeyInfo / SPKI) format.
  - Default key size: 2048 bits (sufficient for the project demo).
  - Keys live in the ``keys/`` directory at repository root.
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


DEFAULT_KEY_SIZE = 2048
DEFAULT_PUBLIC_EXPONENT = 65537


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------
def generate_rsa_keypair(
    bits: int = DEFAULT_KEY_SIZE,
) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate a fresh RSA keypair.

    Returns (private_key, public_key).
    """
    private_key = rsa.generate_private_key(
        public_exponent=DEFAULT_PUBLIC_EXPONENT,
        key_size=bits,
    )
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# Saving
# ---------------------------------------------------------------------------
def save_private_key(
    key: rsa.RSAPrivateKey,
    path: str | Path,
    passphrase: bytes | None = None,
) -> None:
    """Serialize *key* to PEM and write to *path*.

    If *passphrase* is given the key is encrypted with
    ``BestAvailableEncryption``; otherwise it is stored unencrypted.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path.write_bytes(pem)


def save_public_key(key: rsa.RSAPublicKey, path: str | Path) -> None:
    """Serialize *key* to PEM (SPKI) and write to *path*."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def load_private_key(
    path: str | Path,
    passphrase: bytes | None = None,
) -> rsa.RSAPrivateKey:
    """Load a PEM-encoded RSA private key from *path*."""
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=passphrase)


def load_public_key(path: str | Path) -> rsa.RSAPublicKey:
    """Load a PEM-encoded RSA public key from *path*."""
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)
