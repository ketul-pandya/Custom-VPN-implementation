"""
server_main.py — VPN server entry point.

Features:
  - Multi-client TCP server (threaded)
  - Per-connection flow:  accept → IP whitelist check → handshake → serve
  - IP whitelisting  (access control)
  - Rate limiting + connection caps  (availability)
  - Structured logging for audit / demo
  - Configuration via JSON file

Usage::

    python -m server.server_main --config config/server_config.json
"""

import argparse
import json
import logging
import socket
import sys
import threading
from pathlib import Path

from auth.handshake import server_handshake
from auth.key_manager import load_private_key, load_public_key
from crypto.protocol import (
    MessageType,
    send_frame,
    recv_frame,
)
from server.access_control import AccessController
from server.rate_limit import RateLimiter
from server.forwarder import forward_request

logger = logging.getLogger("vpn.server")

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = {
    "listen_ip": "0.0.0.0",
    "listen_port": 4433,
    "server_private_key": "keys/server_private.pem",
    "client_public_key": "keys/client_public.pem",
    "whitelist_file": "config/whitelist.txt",
    "rate_limit_requests_per_second": 10,
    "rate_limit_burst": 20,
    "max_connections_per_ip": 5,
    "max_total_connections": 50,
    "idle_timeout_seconds": 300,
    "log_level": "INFO",
}


def load_config(path: str | None) -> dict:
    """Load config from JSON file; fall back to defaults for missing keys."""
    cfg = dict(DEFAULT_CONFIG)
    if path and Path(path).exists():
        with open(path) as f:
            user_cfg = json.load(f)
        cfg.update(user_cfg)
        logger.info("Configuration loaded from %s", path)
    else:
        logger.info("Using default configuration")
    return cfg


# ---------------------------------------------------------------------------
# Client handler
# ---------------------------------------------------------------------------
def handle_client(
    client_sock: socket.socket,
    client_addr: tuple[str, int],
    server_private_key,
    client_public_key,
    access_ctl: AccessController,
    rate_limiter: RateLimiter,
):
    """Handle a single client connection (thread entry point)."""
    ip = client_addr[0]

    try:
        # ── 1. Access control: IP whitelist ──────────────────────────────
        if not access_ctl.is_allowed(ip):
            logger.warning("AUTH_DENIED  ip=%s  reason=whitelist", ip)
            client_sock.close()
            return

        # ── 2. Connection cap ────────────────────────────────────────────
        if not rate_limiter.try_add_connection(ip):
            logger.warning("AUTH_DENIED  ip=%s  reason=connection_cap", ip)
            client_sock.close()
            return

        try:
            # ── 3. Handshake (mutual authentication) ─────────────────────
            logger.info("HANDSHAKE_START  ip=%s", ip)
            try:
                session_id, enc_key, mac_key = server_handshake(
                    client_sock, server_private_key, client_public_key,
                )
            except Exception as e:
                logger.warning("HANDSHAKE_FAILED  ip=%s  error=%s", ip, e)
                return
            logger.info("HANDSHAKE_OK  ip=%s  session=%s", ip, session_id.hex()[:12])

            # ── 4. Serve requests ────────────────────────────────────────
            client_sock.settimeout(rate_limiter.idle_timeout)

            while True:
                # Check idle timeout
                if rate_limiter.is_idle(ip):
                    logger.info("IDLE_TIMEOUT  ip=%s  session=%s", ip, session_id.hex()[:12])
                    break

                try:
                    msg_type, rx_sid, request_data = recv_frame(
                        client_sock, enc_key=enc_key, mac_key=mac_key,
                    )
                except socket.timeout:
                    logger.info("TIMEOUT  ip=%s  session=%s", ip, session_id.hex()[:12])
                    break
                except ConnectionError:
                    logger.info("DISCONNECTED  ip=%s  session=%s", ip, session_id.hex()[:12])
                    break
                except ValueError as e:
                    logger.warning("FRAME_ERROR  ip=%s  error=%s", ip, e)
                    break

                if msg_type != MessageType.DATA_REQUEST:
                    logger.warning("UNEXPECTED_MSG  ip=%s  type=%s", ip, msg_type.name)
                    continue

                rate_limiter.touch(ip)

                # Rate limit check
                if not rate_limiter.check_rate(ip):
                    error_msg = "Rate limit exceeded — try again later"
                    send_frame(
                        client_sock,
                        MessageType.ERROR,
                        session_id,
                        error_msg.encode("utf-8"),
                        enc_key=enc_key,
                        mac_key=mac_key,
                    )
                    logger.warning(
                        "RATE_LIMITED  ip=%s  session=%s", ip, session_id.hex()[:12],
                    )
                    continue

                # Forward request
                try:
                    response_data = forward_request(request_data)
                except Exception as e:
                    logger.error("FORWARD_ERROR  ip=%s  error=%s", ip, e)
                    response_data = json.dumps({
                        "status_code": 500,
                        "headers": {},
                        "body": f"Forward error: {e}".encode("utf-8").hex(),
                    }).encode("utf-8")

                # Send response back
                send_frame(
                    client_sock,
                    MessageType.DATA_RESPONSE,
                    session_id,
                    response_data,
                    enc_key=enc_key,
                    mac_key=mac_key,
                )

        finally:
            rate_limiter.remove_connection(ip)

    except Exception as e:
        logger.error("CLIENT_ERROR  ip=%s  error=%s", ip, e)
    finally:
        try:
            client_sock.close()
        except Exception:
            pass
        logger.info("CLIENT_CLOSED  ip=%s", ip)


# ---------------------------------------------------------------------------
# Server main loop
# ---------------------------------------------------------------------------
def start_server(cfg: dict):
    """Start the VPN server."""
    listen_ip = cfg["listen_ip"]
    listen_port = cfg["listen_port"]

    # Load keys
    server_priv = load_private_key(cfg["server_private_key"])
    client_pub = load_public_key(cfg["client_public_key"])
    logger.info("RSA keys loaded")

    # Initialise policy modules
    access_ctl = AccessController(cfg.get("whitelist_file"))
    rate_limiter = RateLimiter(
        requests_per_second=cfg.get("rate_limit_requests_per_second", 10),
        burst=cfg.get("rate_limit_burst", 20),
        max_connections_per_ip=cfg.get("max_connections_per_ip", 5),
        max_total_connections=cfg.get("max_total_connections", 50),
        idle_timeout=cfg.get("idle_timeout_seconds", 300),
    )

    # Bind
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_ip, listen_port))
    srv.listen(cfg.get("backlog", 20))
    logger.info("VPN Server listening on %s:%d", listen_ip, listen_port)

    try:
        while True:
            client_sock, client_addr = srv.accept()
            logger.info("CONN_ACCEPT  ip=%s  port=%d", *client_addr)
            t = threading.Thread(
                target=handle_client,
                args=(
                    client_sock, client_addr,
                    server_priv, client_pub,
                    access_ctl, rate_limiter,
                ),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Server shutting down…")
    finally:
        srv.close()
        logger.info("Server socket closed")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="VPN Server")
    parser.add_argument(
        "--config", default="config/server_config.json",
        help="Path to JSON config file",
    )
    # Allow overriding individual settings from CLI
    parser.add_argument("--listen-ip", default=None)
    parser.add_argument("--listen-port", type=int, default=None)
    parser.add_argument("--server-key", default=None)
    parser.add_argument("--client-pubkey", default=None)
    parser.add_argument("--whitelist", default=None)
    parser.add_argument("--log-level", default=None)
    args = parser.parse_args()

    # 1. Setup logging first so we can see config/startup logs
    log_level = args.log_level or "INFO"
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    )

    # 2. Load config
    cfg = load_config(args.config)

    # 3. CLI overrides for other settings
    if args.listen_ip:
        cfg["listen_ip"] = args.listen_ip
    if args.listen_port:
        cfg["listen_port"] = args.listen_port
    if args.server_key:
        cfg["server_private_key"] = args.server_key
    if args.client_pubkey:
        cfg["client_public_key"] = args.client_pubkey
    if args.whitelist:
        cfg["whitelist_file"] = args.whitelist

    start_server(cfg)


if __name__ == "__main__":
    main()
