"""
forwarder.py — Forward client requests to target web servers.

Handles:
  - Regular HTTP requests (GET, POST, etc.)
  - CONNECT tunnelling (raw TCP relay for HTTPS)
  - Large response streaming
  - Timeout handling
"""

import json
import logging
import socket
import requests as http_requests

logger = logging.getLogger("vpn.forwarder")

DEFAULT_TIMEOUT = 15         # seconds
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# Active CONNECT sessions  (url → socket to target)
_connect_sessions: dict[str, socket.socket] = {}
_connect_lock = __import__("threading").Lock()


def forward_request(request_data: bytes) -> bytes:
    """Parse the canonical request format and forward to the target.

    Returns the canonical response format as bytes.
    """
    try:
        req = json.loads(request_data.decode("utf-8"))
    except Exception as e:
        return _error_response(400, f"Bad request format: {e}")

    method = req.get("method", "GET").upper()
    url = req.get("url", "")
    headers = req.get("headers", {})
    body_hex = req.get("body", "")
    body = bytes.fromhex(body_hex) if body_hex else b""

    if method == "CONNECT":
        return _handle_connect(url)
    elif method == "RELAY":
        return _handle_relay(url, body)
    else:
        return _handle_http(method, url, headers, body)


# ---------------------------------------------------------------------------
# Regular HTTP forwarding
# ---------------------------------------------------------------------------
def _handle_http(method: str, url: str, headers: dict, body: bytes) -> bytes:
    """Forward a standard HTTP request."""
    # Ensure URL has a scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # Set a reasonable User-Agent if not provided
    if "User-Agent" not in headers:
        headers["User-Agent"] = USER_AGENT

    # Remove proxy-specific headers
    for hdr in ("Proxy-Connection", "Proxy-Authorization"):
        headers.pop(hdr, None)

    try:
        logger.info("FORWARD  %s %s", method, url)
        resp = http_requests.request(
            method=method,
            url=url,
            headers=headers,
            data=body if body else None,
            timeout=DEFAULT_TIMEOUT,
            allow_redirects=True,
            verify=True,
            stream=True,
        )

        # Read the full response body (streaming)
        content = b""
        for chunk in resp.iter_content(chunk_size=65536):
            content += chunk

        # Build response header dict
        resp_headers = dict(resp.headers)

        logger.info(
            "RESPONSE  %s %s → %d  (%d bytes)",
            method, url, resp.status_code, len(content),
        )

        return _build_response(resp.status_code, resp_headers, content)

    except http_requests.exceptions.Timeout:
        logger.warning("TIMEOUT  %s %s", method, url)
        return _error_response(504, f"Timeout connecting to {url}")
    except http_requests.exceptions.ConnectionError as e:
        logger.warning("CONN_ERROR  %s %s: %s", method, url, e)
        return _error_response(502, f"Connection error: {e}")
    except http_requests.exceptions.RequestException as e:
        logger.warning("REQUEST_ERROR  %s %s: %s", method, url, e)
        return _error_response(502, f"Request error: {e}")
    except Exception as e:
        logger.error("UNEXPECTED_ERROR  %s %s: %s", method, url, e)
        return _error_response(500, f"Server error: {e}")


# ---------------------------------------------------------------------------
# CONNECT tunnelling  (HTTPS support)
# ---------------------------------------------------------------------------
def _handle_connect(target: str) -> bytes:
    """Open a raw TCP connection to *target* (host:port) for HTTPS tunnelling."""
    try:
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            port = int(port_str)
        else:
            host, port = target, 443

        logger.info("CONNECT  %s:%d", host, port)
        target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_sock.settimeout(DEFAULT_TIMEOUT)
        target_sock.connect((host, port))
        target_sock.settimeout(5)  # for relay reads

        with _connect_lock:
            _connect_sessions[target] = target_sock

        return _build_response(200, {}, b"")

    except Exception as e:
        logger.warning("CONNECT failed %s: %s", target, e)
        return _error_response(502, f"CONNECT failed: {e}")


def _handle_relay(target: str, data: bytes) -> bytes:
    """Relay raw bytes for an established CONNECT tunnel."""
    with _connect_lock:
        target_sock = _connect_sessions.get(target)

    if target_sock is None:
        return _error_response(502, f"No CONNECT session for {target}")

    try:
        # Send data to target
        if data:
            target_sock.sendall(data)

        # Read response from target
        response_data = b""
        try:
            while True:
                chunk = target_sock.recv(65536)
                if not chunk:
                    # Target closed connection
                    with _connect_lock:
                        _connect_sessions.pop(target, None)
                    return json.dumps({
                        "status_code": 200,
                        "headers": {},
                        "body": response_data.hex(),
                        "closed": True,
                    }).encode("utf-8")
                response_data += chunk
                # Don't block forever — if no more data available, return what we have
                if len(chunk) < 65536:
                    break
        except socket.timeout:
            pass
        except Exception:
            pass

        return json.dumps({
            "status_code": 200,
            "headers": {},
            "body": response_data.hex(),
            "closed": False,
        }).encode("utf-8")

    except Exception as e:
        logger.warning("RELAY error %s: %s", target, e)
        with _connect_lock:
            _connect_sessions.pop(target, None)
        try:
            target_sock.close()
        except Exception:
            pass
        return _error_response(502, f"Relay error: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _build_response(status_code: int, headers: dict, body: bytes) -> bytes:
    return json.dumps({
        "status_code": status_code,
        "headers": {k: v for k, v in headers.items()},
        "body": body.hex(),
    }).encode("utf-8")


def _error_response(status_code: int, message: str) -> bytes:
    body = f"<html><body><h1>{status_code}</h1><p>{message}</p></body></html>"
    return _build_response(
        status_code,
        {"Content-Type": "text/html"},
        body.encode("utf-8"),
    )
