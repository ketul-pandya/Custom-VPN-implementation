"""
tunnel_client.py — Manages a single authenticated, encrypted tunnel to the
VPN server.

Usage::

    tc = TunnelClient(server_host, server_port, client_priv, server_pub)
    tc.connect()           # TCP connect + handshake
    resp = tc.send_request(request_bytes)
    tc.close()

The class is thread-safe: a lock serialises frame sends/receives so
multiple browser-handling threads can share one tunnel.
"""

import logging
import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric import rsa

from crypto.protocol import (
    MessageType,
    send_frame,
    recv_frame,
)
from auth.handshake import client_handshake

logger = logging.getLogger("vpn.tunnel_client")


class TunnelClient:
    """Persistent, authenticated tunnel to the VPN server."""

    def __init__(
        self,
        server_host: str,
        server_port: int,
        client_private_key: rsa.RSAPrivateKey,
        server_public_key: rsa.RSAPublicKey,
        connect_timeout: float = 10.0,
        io_timeout: float = 60.0,
        max_retries: int = 3,
        retry_backoff: float = 2.0,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.client_private_key = client_private_key
        self.server_public_key = server_public_key
        self.connect_timeout = connect_timeout
        self.io_timeout = io_timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff

        self._sock: socket.socket | None = None
        self._session_id: bytes | None = None
        self._enc_key: bytes | None = None
        self._mac_key: bytes | None = None
        self._lock = threading.Lock()
        self._connected = False

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------
    def connect(self) -> None:
        """Establish TCP connection and run handshake."""
        with self._lock:
            self._do_connect()

    def _do_connect(self) -> None:
        self._close_socket()
        logger.info("Connecting to %s:%d …", self.server_host, self.server_port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.connect_timeout)
        sock.connect((self.server_host, self.server_port))
        sock.settimeout(self.io_timeout)
        logger.info("TCP connected, starting handshake …")

        sid, enc, mac = client_handshake(
            sock, self.client_private_key, self.server_public_key,
        )
        self._sock = sock
        self._session_id = sid
        self._enc_key = enc
        self._mac_key = mac
        self._connected = True
        logger.info("Tunnel established  session=%s", sid.hex()[:12])

    def close(self) -> None:
        """Close the tunnel."""
        with self._lock:
            self._close_socket()

    def _close_socket(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        self._sock = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    # ------------------------------------------------------------------
    # Request / response (thread-safe)
    # ------------------------------------------------------------------
    def send_request(self, request_data: bytes) -> bytes:
        """Send a request through the tunnel and return the response.

        Automatically reconnects with backoff on failure (up to *max_retries*).

        Returns the decrypted response bytes.
        """
        last_err: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return self._do_request(request_data)
            except Exception as e:
                last_err = e
                logger.warning(
                    "Tunnel request failed (attempt %d/%d): %s",
                    attempt, self.max_retries, e,
                )
                # Try to reconnect
                try:
                    with self._lock:
                        self._do_connect()
                except Exception as ce:
                    logger.warning("Reconnect failed: %s", ce)
                if attempt < self.max_retries:
                    time.sleep(self.retry_backoff * attempt)

        raise ConnectionError(
            f"Tunnel request failed after {self.max_retries} attempts: {last_err}"
        )

    def _do_request(self, request_data: bytes) -> bytes:
        with self._lock:
            if not self._connected or self._sock is None:
                self._do_connect()

            send_frame(
                self._sock,
                MessageType.DATA_REQUEST,
                self._session_id,
                request_data,
                enc_key=self._enc_key,
                mac_key=self._mac_key,
            )

            msg_type, _sid, response = recv_frame(
                self._sock,
                enc_key=self._enc_key,
                mac_key=self._mac_key,
            )

            if msg_type == MessageType.ERROR:
                raise RuntimeError(f"Server error: {response.decode('utf-8', errors='replace')}")

            if msg_type != MessageType.DATA_RESPONSE:
                raise ValueError(f"Unexpected message type: {msg_type.name}")

            return response
