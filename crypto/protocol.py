"""
protocol.py — Wire-protocol framing for the VPN tunnel.

Frame layout (sent over TCP):
  ┌──────────┬──────────┬──────────────┬───────┬──────────────────┬──────────┐
  │ 4 bytes  │ 1 byte   │ 16 bytes     │ 12 B  │ variable         │ 32 bytes │
  │ total_len│ msg_type │ session_id   │ nonce │ encrypted payload│ HMAC     │
  └──────────┴──────────┴──────────────┴───────┴──────────────────┴──────────┘

  total_len  = len(msg_type + session_id + nonce + encrypted_payload + hmac)
             = 1 + 16 + 12 + len(enc_payload) + 32

  HMAC covers everything *except* total_len and the HMAC itself:
    HMAC(msg_type || session_id || nonce || encrypted_payload)

For **handshake** messages the payload is NOT encrypted (no session key yet).
The HMAC is still present; during handshake a temporary HMAC key (all zeros or
a pre-shared bootstrap value) is used, and after handshake the derived mac_key
is used.
"""

import enum
import struct
import socket
import logging

from .crypto_utils import (
    encrypt_payload,
    decrypt_payload,
    compute_hmac,
    verify_hmac,
    GCM_NONCE_SIZE,
    HMAC_DIGEST_SIZE,
)

logger = logging.getLogger("vpn.protocol")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
HEADER_FMT = "!I"                    # 4-byte big-endian unsigned int (total_len)
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 4
SESSION_ID_SIZE = 16
MAX_FRAME_SIZE = 16 * 1024 * 1024    # 16 MiB safety cap

# A "null" HMAC key used during the handshake before a session key exists.
HANDSHAKE_HMAC_KEY = b"\x00" * 32


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------
class MessageType(enum.IntEnum):
    """One-byte message type codes."""
    HANDSHAKE_CLIENT_HELLO    = 0x01
    HANDSHAKE_SERVER_HELLO    = 0x02
    HANDSHAKE_CLIENT_RESPONSE = 0x03
    HANDSHAKE_SERVER_DONE     = 0x04

    DATA_REQUEST              = 0x10
    DATA_RESPONSE             = 0x11

    ERROR                     = 0xFF


# ---------------------------------------------------------------------------
# Low-level TCP helpers
# ---------------------------------------------------------------------------
def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from *sock*, handling partial reads.

    Raises ``ConnectionError`` if the peer closes the connection before
    all bytes have been received.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Connection closed after receiving {len(buf)}/{n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Frame send / receive  (the public API)
# ---------------------------------------------------------------------------
def send_frame(
    sock: socket.socket,
    msg_type: MessageType,
    session_id: bytes,
    payload: bytes,
    enc_key: bytes | None = None,
    mac_key: bytes | None = None,
) -> None:
    """Serialize and send one frame.

    If *enc_key* is provided the payload is encrypted with AES-256-GCM;
    otherwise it is sent in cleartext (used for handshake messages).

    *mac_key* is used for the outer HMAC.  If ``None``,
    ``HANDSHAKE_HMAC_KEY`` is used (handshake phase).
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise ValueError(
            f"session_id must be {SESSION_ID_SIZE} bytes, got {len(session_id)}"
        )

    mac_key = mac_key or HANDSHAKE_HMAC_KEY

    # --- optionally encrypt -----------
    if enc_key is not None:
        enc_payload, nonce = encrypt_payload(payload, enc_key)
    else:
        # cleartext: nonce field is still present but zeroed
        enc_payload = payload
        nonce = b"\x00" * GCM_NONCE_SIZE

    # --- build body (everything after total_len, before HMAC) ---
    body = bytes([int(msg_type)]) + session_id + nonce + enc_payload

    # --- HMAC over body ---
    mac = compute_hmac(body, mac_key)

    # --- total_len = len(body) + HMAC ---
    total_len = len(body) + HMAC_DIGEST_SIZE
    if total_len > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {total_len} > {MAX_FRAME_SIZE}")

    frame = struct.pack(HEADER_FMT, total_len) + body + mac
    sock.sendall(frame)
    logger.debug(
        "TX  type=%s  payload=%d  frame=%d",
        MessageType(msg_type).name, len(payload), len(frame),
    )


def recv_frame(
    sock: socket.socket,
    enc_key: bytes | None = None,
    mac_key: bytes | None = None,
) -> tuple[MessageType, bytes, bytes]:
    """Receive and validate one frame.

    Returns:
        (msg_type, session_id, payload)

    Payload is decrypted if *enc_key* is provided; otherwise returned raw
    (handshake messages).

    Raises:
        ``ConnectionError`` on unexpected disconnect.
        ``ValueError`` on HMAC failure or corrupt frame.
    """
    mac_key = mac_key or HANDSHAKE_HMAC_KEY

    # --- read total_len header ---
    header = recv_exact(sock, HEADER_SIZE)
    (total_len,) = struct.unpack(HEADER_FMT, header)

    if total_len > MAX_FRAME_SIZE:
        raise ValueError(f"Frame too large: {total_len} > {MAX_FRAME_SIZE}")

    # Minimum size: 1 (type) + 16 (sid) + 12 (nonce) + 0 (payload) + 32 (hmac)
    min_body = 1 + SESSION_ID_SIZE + GCM_NONCE_SIZE + HMAC_DIGEST_SIZE
    if total_len < min_body:
        raise ValueError(f"Frame too small: {total_len} < {min_body}")

    # --- read the rest of the frame ---
    raw = recv_exact(sock, total_len)

    # --- split HMAC off the end ---
    body = raw[:-HMAC_DIGEST_SIZE]
    received_mac = raw[-HMAC_DIGEST_SIZE:]

    # --- verify HMAC ---
    if not verify_hmac(body, received_mac, mac_key):
        raise ValueError("HMAC verification failed — frame may be tampered")

    # --- parse body ---
    msg_type = MessageType(body[0])
    session_id = body[1 : 1 + SESSION_ID_SIZE]
    nonce = body[1 + SESSION_ID_SIZE : 1 + SESSION_ID_SIZE + GCM_NONCE_SIZE]
    enc_payload = body[1 + SESSION_ID_SIZE + GCM_NONCE_SIZE :]

    # --- decrypt if we have a key ---
    if enc_key is not None:
        payload = decrypt_payload(enc_payload, nonce, enc_key)
    else:
        payload = enc_payload

    logger.debug(
        "RX  type=%s  payload=%d  frame=%d",
        msg_type.name, len(payload), total_len + HEADER_SIZE,
    )
    return msg_type, session_id, payload
