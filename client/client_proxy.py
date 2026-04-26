"""
client_proxy.py — Local HTTP/HTTPS proxy that tunnels traffic through the
encrypted VPN tunnel.

Browsers connect to this local proxy.  The proxy:
 1. Accepts HTTP / HTTPS-CONNECT requests from the browser.
 2. Serialises them into a canonical format.
 3. Encrypts + frames them via the TunnelClient.
 4. Decrypts the response and sends it back to the browser.

Usage::

    python -m client.client_proxy \\
        --server-host 127.0.0.1 --server-port 4433 \\
        --proxy-port 8888 \\
        --client-key keys/client_private.pem \\
        --server-pubkey keys/server_public.pem
"""

import argparse
import json
import logging
import socket
import sys
import threading

from auth.key_manager import load_private_key, load_public_key
from client.tunnel_client import TunnelClient

logger = logging.getLogger("vpn.client_proxy")

BUFFER_SIZE = 65536   # 64 KiB per-recv


# ---------------------------------------------------------------------------
# Request / response canonical format  (JSON over the tunnel)
# ---------------------------------------------------------------------------
def _encode_request(method: str, url: str, headers: dict, body: bytes) -> bytes:
    """Pack an HTTP request into the canonical tunnel format."""
    return json.dumps({
        "method": method,
        "url": url,
        "headers": headers,
        "body": body.hex() if body else "",
    }).encode("utf-8")


def _decode_response(data: bytes) -> tuple[int, dict, bytes]:
    """Unpack a tunnel response into (status_code, headers, body)."""
    obj = json.loads(data.decode("utf-8"))
    return (
        obj["status_code"],
        obj.get("headers", {}),
        bytes.fromhex(obj["body"]) if obj.get("body") else b"",
    )


# ---------------------------------------------------------------------------
# CONNECT tunnelling (HTTPS)
# ---------------------------------------------------------------------------
def _handle_connect(
    browser_sock: socket.socket,
    target_host: str,
    target_port: int,
    tunnel: TunnelClient,
):
    """Handle HTTPS CONNECT — bidirectional byte-level tunnel."""
    # Tell the browser the tunnel is established
    browser_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # For CONNECT we send raw bytes through the VPN tunnel
    # Each chunk from the browser is forwarded as a DATA_REQUEST,
    # and the response from the target (via the server) is forwarded back.
    #
    # The canonical format for CONNECT wraps raw bytes:
    connect_req = json.dumps({
        "method": "CONNECT",
        "url": f"{target_host}:{target_port}",
        "headers": {},
        "body": "",
    }).encode("utf-8")

    try:
        # Send initial CONNECT to the server so it opens a socket to target
        resp_bytes = tunnel.send_request(connect_req)
        resp = json.loads(resp_bytes.decode("utf-8"))
        if resp.get("status_code", 0) != 200:
            logger.warning("Server refused CONNECT: %s", resp)
            return

        # Now relay raw bytes  (browser <-> tunnel) in both directions
        browser_sock.setblocking(False)

        while True:
            # Read from browser (non-blocking)
            try:
                data = browser_sock.recv(BUFFER_SIZE)
                if not data:
                    break
                # Send to server as raw relay
                relay_req = json.dumps({
                    "method": "RELAY",
                    "url": f"{target_host}:{target_port}",
                    "headers": {},
                    "body": data.hex(),
                }).encode("utf-8")
                relay_resp = tunnel.send_request(relay_req)
                rr = json.loads(relay_resp.decode("utf-8"))
                if rr.get("body"):
                    browser_sock.sendall(bytes.fromhex(rr["body"]))
                if rr.get("closed"):
                    break
            except BlockingIOError:
                pass
            except Exception as e:
                logger.debug("CONNECT relay error: %s", e)
                break

    except Exception as e:
        logger.warning("CONNECT tunnel error: %s", e)


# ---------------------------------------------------------------------------
# HTTP proxying
# ---------------------------------------------------------------------------
def _handle_http_request(
    browser_sock: socket.socket,
    method: str,
    url: str,
    headers_str: str,
    body: bytes,
    tunnel: TunnelClient,
):
    """Forward a plain HTTP request through the VPN tunnel."""
    # Parse headers
    headers = {}
    for line in headers_str.split("\r\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    request_bytes = _encode_request(method, url, headers, body)

    try:
        response_bytes = tunnel.send_request(request_bytes)
        status_code, resp_headers, resp_body = _decode_response(response_bytes)
    except Exception as e:
        logger.error("Tunnel request failed: %s", e)
        error_page = (
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body><h1>502 Bad Gateway</h1>"
            b"<p>VPN tunnel error: " + str(e).encode() + b"</p>"
            b"</body></html>"
        )
        try:
            browser_sock.sendall(error_page)
        except Exception:
            pass
        return

    # Build raw HTTP response for the browser
    status_line = f"HTTP/1.1 {status_code} OK\r\n"
    header_lines = ""
    for k, v in resp_headers.items():
        # Skip hop-by-hop headers
        if k.lower() in ("transfer-encoding", "connection", "keep-alive"):
            continue
        header_lines += f"{k}: {v}\r\n"
    header_lines += f"Content-Length: {len(resp_body)}\r\n"
    header_lines += "Connection: close\r\n"

    raw_response = (status_line + header_lines + "\r\n").encode("utf-8") + resp_body
    try:
        browser_sock.sendall(raw_response)
    except socket.error as e:
        logger.debug("Send to browser failed: %s", e)


# ---------------------------------------------------------------------------
# Browser connection handler
# ---------------------------------------------------------------------------
def handle_browser(browser_sock: socket.socket, tunnel: TunnelClient):
    """Handle one browser connection (thread entry point)."""
    try:
        # Read the initial HTTP request
        raw = browser_sock.recv(BUFFER_SIZE)
        if not raw:
            return

        request_text = raw.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        if not lines:
            return

        first_line = lines[0]
        parts = first_line.split(" ")
        if len(parts) < 3:
            logger.warning("Malformed request: %s", first_line)
            return

        method = parts[0].upper()
        target = parts[1]

        logger.info("Browser: %s %s", method, target)

        if method == "CONNECT":
            # HTTPS — target is host:port
            if ":" in target:
                host, port_str = target.rsplit(":", 1)
                port = int(port_str)
            else:
                host, port = target, 443
            _handle_connect(browser_sock, host, port, tunnel)
        else:
            # HTTP — target is full URL (absolute form when using proxy)
            # Split headers and body
            header_body = request_text.split("\r\n\r\n", 1)
            headers_section = header_body[0]
            body = header_body[1].encode("utf-8") if len(header_body) > 1 else b""
            # Remove the request line from headers
            header_lines = "\r\n".join(headers_section.split("\r\n")[1:])
            _handle_http_request(
                browser_sock, method, target, header_lines, body, tunnel,
            )
    except Exception as e:
        logger.error("Error handling browser connection: %s", e)
    finally:
        try:
            browser_sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Local proxy server
# ---------------------------------------------------------------------------
def start_proxy(
    proxy_host: str,
    proxy_port: int,
    tunnel: TunnelClient,
):
    """Start the local HTTP proxy server."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((proxy_host, proxy_port))
    srv.listen(20)
    logger.info("Local proxy listening on %s:%d", proxy_host, proxy_port)
    logger.info("Configure your browser proxy to %s:%d", proxy_host, proxy_port)

    try:
        while True:
            browser_sock, addr = srv.accept()
            logger.debug("Browser connected from %s", addr)
            t = threading.Thread(
                target=handle_browser,
                args=(browser_sock, tunnel),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy…")
    finally:
        srv.close()
        tunnel.close()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="VPN Client — Local HTTP/HTTPS proxy with encrypted tunnel",
    )
    parser.add_argument("--server-host", default="127.0.0.1",
                        help="VPN server hostname/IP (default: 127.0.0.1)")
    parser.add_argument("--server-port", type=int, default=4433,
                        help="VPN server port (default: 4433)")
    parser.add_argument("--proxy-host", default="127.0.0.1",
                        help="Local proxy listen IP (default: 127.0.0.1)")
    parser.add_argument("--proxy-port", type=int, default=8888,
                        help="Local proxy listen port (default: 8888)")
    parser.add_argument("--client-key", default="keys/client_private.pem",
                        help="Path to client RSA private key")
    parser.add_argument("--server-pubkey", default="keys/server_public.pem",
                        help="Path to server RSA public key")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    )

    client_priv = load_private_key(args.client_key)
    server_pub = load_public_key(args.server_pubkey)

    tunnel = TunnelClient(
        server_host=args.server_host,
        server_port=args.server_port,
        client_private_key=client_priv,
        server_public_key=server_pub,
    )

    logger.info("Connecting to VPN server…")
    tunnel.connect()
    logger.info("Tunnel established!")

    start_proxy(args.proxy_host, args.proxy_port, tunnel)


if __name__ == "__main__":
    main()
