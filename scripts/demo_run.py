#!/usr/bin/env python3
"""
demo_run.py — Automated demo: generate keys, start server + client,
make sample requests.

This script demonstrates the full VPN pipeline end-to-end and exercises
the security features needed for the project evaluation.

Usage::

    python scripts/demo_run.py

The script will:
  1. Generate fresh keypairs (if not present)
  2. Start the VPN server in a background thread
  3. Start the VPN client proxy in a background thread
  4. Make several HTTP requests through the proxy
  5. Report results and exit
"""

import json
import os
import socket
import subprocess
import sys
import time
import threading
import urllib.request
import urllib.error

# Allow running from repo root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

KEYS_DIR = os.path.join(ROOT, "keys")
SERVER_PORT = 4433
PROXY_PORT = 8888
TEST_URLS = [
    "http://httpbin.org/get",
    "http://example.com",
    "http://httpbin.org/ip",
]


def ensure_keys():
    """Generate keys if they don't exist."""
    if not os.path.exists(os.path.join(KEYS_DIR, "server_private.pem")):
        print("\n[1/5] Generating keys...")
        subprocess.run(
            [sys.executable, os.path.join(ROOT, "scripts", "generate_keys.py")],
            check=True,
        )
    else:
        print("\n[1/5] Keys already exist [OK]")


def start_server():
    """Start the VPN server in a subprocess."""
    print("\n[2/5] Starting VPN server on port", SERVER_PORT, "...")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "server.server_main",
            "--listen-ip", "127.0.0.1",
            "--listen-port", str(SERVER_PORT),
            "--server-key", os.path.join(KEYS_DIR, "server_private.pem"),
            "--client-pubkey", os.path.join(KEYS_DIR, "client_public.pem"),
            "--whitelist", os.path.join(ROOT, "config", "whitelist.txt"),
            "--log-level", "INFO",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(2)
    if proc.poll() is not None:
        out = proc.stdout.read().decode(errors="replace")
        safe_out = out.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8')
        print(f"  [ERROR] Server failed to start:\n{safe_out}")
        sys.exit(1)
    print("  [OK] Server started (PID", proc.pid, ")")
    return proc


def start_client():
    """Start the VPN client proxy in a subprocess."""
    print("\n[3/5] Starting VPN client proxy on port", PROXY_PORT, "...")
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "client.client_proxy",
            "--server-host", "127.0.0.1",
            "--server-port", str(SERVER_PORT),
            "--proxy-port", str(PROXY_PORT),
            "--client-key", os.path.join(KEYS_DIR, "client_private.pem"),
            "--server-pubkey", os.path.join(KEYS_DIR, "server_public.pem"),
            "--log-level", "INFO",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(3)  # handshake takes a moment
    if proc.poll() is not None:
        out = proc.stdout.read().decode(errors="replace")
        safe_out = out.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8')
        print(f"  [ERROR] Client failed to start:\n{safe_out}")
        sys.exit(1)
    print("  [OK] Client proxy started (PID", proc.pid, ")")
    return proc


def test_requests():
    """Make sample HTTP requests through the proxy."""
    print("\n[4/5] Making test requests through VPN tunnel...")

    proxy_handler = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{PROXY_PORT}",
    })
    opener = urllib.request.build_opener(proxy_handler)

    results = []
    for url in TEST_URLS:
        try:
            resp = opener.open(url, timeout=15)
            body = resp.read()
            status = resp.getcode()
            print(f"  [OK] {url}  -> {status}  ({len(body)} bytes)")
            results.append(("PASS", url, status, len(body)))
        except Exception as e:
            print(f"  [FAIL] {url}  -> ERROR: {e}")
            results.append(("FAIL", url, str(e), 0))

    return results


def print_report(results):
    """Print summary."""
    print("\n[5/5] Summary")
    print("=" * 60)
    passed = sum(1 for r in results if r[0] == "PASS")
    print(f"  {passed}/{len(results)} requests succeeded through VPN tunnel")
    if passed == len(results):
        print("  [OK] All tests passed - tunnel is working!")
    else:
        print("  [WARN] Some tests failed - check server/client logs")
    print("=" * 60)


def main():
    print("=" * 60)
    print("  Custom VPN - End-to-End Demo")
    print("=" * 60)

    ensure_keys()

    server_proc = start_server()
    client_proc = None

    try:
        client_proc = start_client()
        results = test_requests()
        print_report(results)
    except KeyboardInterrupt:
        print("\nDemo interrupted.")
    finally:
        print("\nCleaning up...")
        if client_proc:
            client_proc.terminate()
            client_proc.wait(timeout=5)
        server_proc.terminate()
        server_proc.wait(timeout=5)
        print("Done.")


if __name__ == "__main__":
    main()
