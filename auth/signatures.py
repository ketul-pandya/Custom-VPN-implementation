"""
signatures.py — RSA-PSS digital signature helpers.

Used during the handshake to provide **non-repudiation**: each side signs
the handshake transcript so a third party can later verify that the
session was established by the claimed key holder.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """Sign *data* with RSA-PSS (SHA-256).

    Returns the raw signature bytes.
    """
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(
    data: bytes,
    signature: bytes,
    public_key: rsa.RSAPublicKey,
) -> bool:
    """Verify an RSA-PSS signature.

    Returns ``True`` if valid, ``False`` on any failure.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
