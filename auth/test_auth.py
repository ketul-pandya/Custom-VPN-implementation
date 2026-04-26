"""
test_auth.py — Unit tests for the authentication / handshake module.

Run with:  python -m pytest auth/test_auth.py -v
"""

import os
import socket
import threading
import time
import pytest

from auth.key_manager import (
    generate_rsa_keypair,
    save_private_key,
    load_private_key,
    save_public_key,
    load_public_key,
)
from auth.signatures import sign_data, verify_signature
from auth.handshake import client_handshake, server_handshake


# ── helpers ──────────────────────────────────────────────────────────────────
def _socketpair():
    """Create a connected TCP socket pair via loopback."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.connect(("127.0.0.1", port))
    s, _ = srv.accept()
    srv.close()
    return c, s


# ── Signature tests ─────────────────────────────────────────────────────────
class TestSignatures:
    def test_sign_verify(self):
        priv, pub = generate_rsa_keypair()
        data = b"hello world"
        sig = sign_data(data, priv)
        assert verify_signature(data, sig, pub)

    def test_wrong_data_fails(self):
        priv, pub = generate_rsa_keypair()
        sig = sign_data(b"hello", priv)
        assert not verify_signature(b"world", sig, pub)

    def test_wrong_key_fails(self):
        priv1, pub1 = generate_rsa_keypair()
        _priv2, pub2 = generate_rsa_keypair()
        sig = sign_data(b"data", priv1)
        assert verify_signature(b"data", sig, pub1)
        assert not verify_signature(b"data", sig, pub2)


# ── Key manager tests ───────────────────────────────────────────────────────
class TestKeyManager:
    def test_save_load_private(self, tmp_path):
        priv, _ = generate_rsa_keypair()
        path = tmp_path / "test.pem"
        save_private_key(priv, path)
        loaded = load_private_key(path)
        # Compare by signing with both
        data = b"test data"
        sig = sign_data(data, loaded)
        assert verify_signature(data, sig, priv.public_key())

    def test_save_load_public(self, tmp_path):
        _, pub = generate_rsa_keypair()
        path = tmp_path / "test_pub.pem"
        save_public_key(pub, path)
        loaded = load_public_key(path)
        # Compare by verifying with loaded key
        priv, pub = generate_rsa_keypair()
        save_public_key(pub, path)
        loaded = load_public_key(path)
        sig = sign_data(b"test", priv)
        assert verify_signature(b"test", sig, loaded)

    def test_encrypted_private_key(self, tmp_path):
        priv, _ = generate_rsa_keypair()
        path = tmp_path / "enc.pem"
        save_private_key(priv, path, passphrase=b"hunter2")
        loaded = load_private_key(path, passphrase=b"hunter2")
        sig = sign_data(b"ok", loaded)
        assert verify_signature(b"ok", sig, priv.public_key())

    def test_wrong_passphrase(self, tmp_path):
        priv, _ = generate_rsa_keypair()
        path = tmp_path / "enc.pem"
        save_private_key(priv, path, passphrase=b"correct")
        with pytest.raises(Exception):
            load_private_key(path, passphrase=b"wrong")


# ── Handshake tests ─────────────────────────────────────────────────────────
class TestHandshake:
    def _run_handshake(self, client_priv, client_pub, server_priv, server_pub):
        """Run a full handshake over a loopback socket pair, return results."""
        c_sock, s_sock = _socketpair()
        results = {}
        errors = {}

        def _server():
            try:
                sid, enc, mac = server_handshake(s_sock, server_priv, client_pub)
                results["server"] = (sid, enc, mac)
            except Exception as e:
                errors["server"] = e
            finally:
                s_sock.close()

        def _client():
            try:
                sid, enc, mac = client_handshake(c_sock, client_priv, server_pub)
                results["client"] = (sid, enc, mac)
            except Exception as e:
                errors["client"] = e
            finally:
                c_sock.close()

        st = threading.Thread(target=_server)
        ct = threading.Thread(target=_client)
        st.start()
        ct.start()
        st.join(timeout=10)
        ct.join(timeout=10)
        return results, errors

    def test_successful_handshake(self):
        """Both sides complete and agree on keys."""
        s_priv, s_pub = generate_rsa_keypair()
        c_priv, c_pub = generate_rsa_keypair()
        results, errors = self._run_handshake(c_priv, c_pub, s_priv, s_pub)
        assert not errors, f"Handshake errors: {errors}"
        assert "server" in results and "client" in results
        # session_id, enc_key, mac_key must match
        assert results["server"][0] == results["client"][0]  # session_id
        assert results["server"][1] == results["client"][1]  # enc_key
        assert results["server"][2] == results["client"][2]  # mac_key

    def test_wrong_server_key_fails(self):
        """Client rejects if server uses a different key than expected."""
        s_priv, s_pub = generate_rsa_keypair()
        c_priv, c_pub = generate_rsa_keypair()
        # Give client a *different* server public key
        _, wrong_pub = generate_rsa_keypair()
        results, errors = self._run_handshake(c_priv, c_pub, s_priv, wrong_pub)
        assert "client" in errors  # client should reject

    def test_wrong_client_key_fails(self):
        """Server rejects if client uses a different key than expected."""
        s_priv, s_pub = generate_rsa_keypair()
        c_priv, c_pub = generate_rsa_keypair()
        # Give server a *different* client public key
        _, wrong_pub = generate_rsa_keypair()
        results, errors = self._run_handshake(c_priv, wrong_pub, s_priv, s_pub)
        assert "server" in errors  # server should reject


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
