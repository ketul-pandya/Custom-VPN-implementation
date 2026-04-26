"""
test_crypto.py — Unit tests and test vectors for the crypto module.

Run with:  python -m pytest crypto/test_crypto.py -v
"""

import os
import socket
import threading
import struct
import pytest

from crypto.crypto_utils import (
    generate_session_key,
    encrypt_payload,
    decrypt_payload,
    compute_hmac,
    verify_hmac,
    derive_keys,
    AES_KEY_SIZE,
    GCM_NONCE_SIZE,
    HMAC_DIGEST_SIZE,
)
from crypto.protocol import (
    MessageType,
    send_frame,
    recv_frame,
    HEADER_SIZE,
    SESSION_ID_SIZE,
    HANDSHAKE_HMAC_KEY,
)


# ── helpers ──────────────────────────────────────────────────────────────────
def _socketpair():
    """Create a connected pair of TCP sockets via loopback."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    peer, _ = srv.accept()
    srv.close()
    return client, peer


# ── AES-GCM encrypt / decrypt ───────────────────────────────────────────────
class TestAESGCM:
    def test_round_trip(self):
        """Encrypt then decrypt returns original plaintext."""
        key = generate_session_key()
        plaintext = b"Hello, world!"
        ct, nonce = encrypt_payload(plaintext, key)
        result = decrypt_payload(ct, nonce, key)
        assert result == plaintext

    def test_round_trip_large(self):
        """1 MiB payload round-trips correctly."""
        key = generate_session_key()
        plaintext = os.urandom(1024 * 1024)
        ct, nonce = encrypt_payload(plaintext, key)
        result = decrypt_payload(ct, nonce, key)
        assert result == plaintext

    def test_round_trip_empty(self):
        """Empty plaintext works."""
        key = generate_session_key()
        ct, nonce = encrypt_payload(b"", key)
        result = decrypt_payload(ct, nonce, key)
        assert result == b""

    def test_tamper_ciphertext_fails(self):
        """Flipping one byte in ciphertext causes decryption to fail."""
        key = generate_session_key()
        ct, nonce = encrypt_payload(b"secret data", key)
        # Flip the first byte
        tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
        with pytest.raises(Exception):  # InvalidTag
            decrypt_payload(tampered, nonce, key)

    def test_wrong_key_fails(self):
        """Decrypting with a different key fails."""
        key1 = generate_session_key()
        key2 = generate_session_key()
        ct, nonce = encrypt_payload(b"data", key1)
        with pytest.raises(Exception):
            decrypt_payload(ct, nonce, key2)

    def test_wrong_nonce_fails(self):
        """Decrypting with wrong nonce fails."""
        key = generate_session_key()
        ct, nonce = encrypt_payload(b"data", key)
        bad_nonce = os.urandom(GCM_NONCE_SIZE)
        with pytest.raises(Exception):
            decrypt_payload(ct, bad_nonce, key)

    def test_bad_key_length(self):
        """Non-32-byte keys are rejected."""
        with pytest.raises(ValueError):
            encrypt_payload(b"data", b"short")
        with pytest.raises(ValueError):
            decrypt_payload(b"data", os.urandom(GCM_NONCE_SIZE), b"short")


# ── HMAC-SHA256 ─────────────────────────────────────────────────────────────
class TestHMAC:
    def test_valid_hmac(self):
        key = os.urandom(HMAC_DIGEST_SIZE)
        data = b"frame payload bytes"
        mac = compute_hmac(data, key)
        assert len(mac) == HMAC_DIGEST_SIZE
        assert verify_hmac(data, mac, key)

    def test_tampered_data_fails(self):
        key = os.urandom(HMAC_DIGEST_SIZE)
        data = b"frame payload bytes"
        mac = compute_hmac(data, key)
        tampered = data + b"x"
        assert not verify_hmac(tampered, mac, key)

    def test_wrong_key_fails(self):
        k1 = os.urandom(HMAC_DIGEST_SIZE)
        k2 = os.urandom(HMAC_DIGEST_SIZE)
        data = b"frame payload bytes"
        mac = compute_hmac(data, k1)
        assert not verify_hmac(data, mac, k2)


# ── HKDF key derivation ─────────────────────────────────────────────────────
class TestHKDF:
    def test_deterministic(self):
        """Same inputs produce same outputs."""
        ms = b"master-secret-value"
        salt = b"salt-value"
        enc1, mac1 = derive_keys(ms, salt)
        enc2, mac2 = derive_keys(ms, salt)
        assert enc1 == enc2
        assert mac1 == mac2

    def test_key_lengths(self):
        enc, mac = derive_keys(b"secret")
        assert len(enc) == AES_KEY_SIZE
        assert len(mac) == HMAC_DIGEST_SIZE

    def test_different_secrets_differ(self):
        enc1, mac1 = derive_keys(b"secret-a")
        enc2, mac2 = derive_keys(b"secret-b")
        assert enc1 != enc2
        assert mac1 != mac2


# ── Protocol framing (send / recv over real TCP) ────────────────────────────
class TestFraming:
    def test_cleartext_round_trip(self):
        """Handshake-style frame (no encryption) round-trips."""
        c, s = _socketpair()
        try:
            sid = os.urandom(SESSION_ID_SIZE)
            payload = b"hello handshake"
            send_frame(c, MessageType.HANDSHAKE_CLIENT_HELLO, sid, payload)
            msg_type, rx_sid, rx_payload = recv_frame(s)
            assert msg_type == MessageType.HANDSHAKE_CLIENT_HELLO
            assert rx_sid == sid
            assert rx_payload == payload
        finally:
            c.close()
            s.close()

    def test_encrypted_round_trip(self):
        """Data frame (encrypted) round-trips."""
        c, s = _socketpair()
        try:
            ms = os.urandom(32)
            enc_key, mac_key = derive_keys(ms)
            sid = os.urandom(SESSION_ID_SIZE)
            payload = b"GET http://example.com HTTP/1.1\r\n\r\n"
            send_frame(
                c, MessageType.DATA_REQUEST, sid, payload,
                enc_key=enc_key, mac_key=mac_key
            )
            msg_type, rx_sid, rx_payload = recv_frame(
                s, enc_key=enc_key, mac_key=mac_key
            )
            assert msg_type == MessageType.DATA_REQUEST
            assert rx_sid == sid
            assert rx_payload == payload
        finally:
            c.close()
            s.close()

    def test_large_payload(self):
        """1 MiB payload round-trips through framing."""
        c, s = _socketpair()
        try:
            ms = os.urandom(32)
            enc_key, mac_key = derive_keys(ms)
            sid = os.urandom(SESSION_ID_SIZE)
            payload = os.urandom(1024 * 1024)

            # Send in a thread so recv can drain
            def _send():
                send_frame(
                    c, MessageType.DATA_RESPONSE, sid, payload,
                    enc_key=enc_key, mac_key=mac_key
                )

            t = threading.Thread(target=_send)
            t.start()
            msg_type, rx_sid, rx_payload = recv_frame(
                s, enc_key=enc_key, mac_key=mac_key
            )
            t.join()
            assert rx_payload == payload
        finally:
            c.close()
            s.close()

    def test_hmac_tamper_detected(self):
        """Tampered frame is detected by recv_frame."""
        c, s = _socketpair()
        try:
            sid = os.urandom(SESSION_ID_SIZE)
            send_frame(c, MessageType.DATA_REQUEST, sid, b"payload")

            # Read raw bytes from s and tamper before parsing
            raw_header = s.recv(HEADER_SIZE)
            (total_len,) = struct.unpack("!I", raw_header)
            raw_body = b""
            while len(raw_body) < total_len:
                raw_body += s.recv(total_len - len(raw_body))

            # Flip a byte in the body (not the HMAC)
            tampered = bytearray(raw_body)
            tampered[5] ^= 0xFF
            tampered = bytes(tampered)

            # Feed tampered data back through a new socket pair
            c2, s2 = _socketpair()
            c2.sendall(raw_header + tampered)
            c2.close()

            with pytest.raises(ValueError, match="HMAC"):
                recv_frame(s2)
            s2.close()
        finally:
            c.close()
            s.close()


# ── Known-answer test vector ────────────────────────────────────────────────
class TestKnownAnswerVector:
    def test_encrypt_decrypt_known(self):
        """Verify encrypt → decrypt with a fixed key and data."""
        key = bytes.fromhex(
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef"
        )
        plaintext = b"The quick brown fox jumps over the lazy dog"
        ct, nonce = encrypt_payload(plaintext, key)
        result = decrypt_payload(ct, nonce, key)
        assert result == plaintext

    def test_hmac_known(self):
        """Verify HMAC with known inputs."""
        key = b"known-hmac-key-for-testing-32-by"
        assert len(key) == 32
        data = b"known data"
        mac = compute_hmac(data, key)
        assert verify_hmac(data, mac, key)
        assert not verify_hmac(data + b"!", mac, key)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
