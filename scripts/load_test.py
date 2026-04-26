#!/usr/bin/env python3
"""
load_test.py — Generate rapid concurrent requests to trigger rate limiting.

Usage::

    python scripts/load_test.py [--proxy-port 8888] [--requests 100] [--threads 10]
"""

import argparse
import os
import sys
import threading
import time
import urllib.request
import urllib.error

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


class LoadTestStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.errors = 0
        self.rate_limited = 0
        self.latencies = []

    def record(self, ok, latency, rate_limited=False):
        with self.lock:
            self.total += 1
            if rate_limited:
                self.rate_limited += 1
            elif ok:
                self.success += 1
            else:
                self.errors += 1
            self.latencies.append(latency)


def worker(
    proxy_port: int,
    url: str,
    count: int,
    stats: LoadTestStats,
    worker_id: int,
):
    """Send *count* requests through the proxy."""
    proxy_handler = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{proxy_port}",
    })
    opener = urllib.request.build_opener(proxy_handler)

    for i in range(count):
        start = time.monotonic()
        try:
            resp = opener.open(url, timeout=10)
            body = resp.read()
            latency = time.monotonic() - start

            # Check if response indicates rate limiting
            if resp.getcode() == 429 or b"Rate limit" in body:
                stats.record(False, latency, rate_limited=True)
            else:
                stats.record(True, latency)
        except urllib.error.HTTPError as e:
            latency = time.monotonic() - start
            if e.code == 429 or b"Rate limit" in (e.read() if hasattr(e, 'read') else b""):
                stats.record(False, latency, rate_limited=True)
            else:
                stats.record(False, latency)
        except Exception as e:
            latency = time.monotonic() - start
            if "Rate limit" in str(e) or "502" in str(e) or "429" in str(e):
                stats.record(False, latency, rate_limited=True)
            else:
                stats.record(False, latency)


def main():
    parser = argparse.ArgumentParser(description="Load test for VPN rate limiting")
    parser.add_argument("--proxy-port", type=int, default=8888)
    parser.add_argument("--requests", type=int, default=100,
                        help="Total requests to send")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent threads")
    parser.add_argument("--url", default="http://httpbin.org/get",
                        help="URL to request")
    args = parser.parse_args()

    per_thread = args.requests // args.threads
    stats = LoadTestStats()

    print(f"Load test: {args.requests} requests across {args.threads} threads")
    print(f"Target: {args.url} via proxy 127.0.0.1:{args.proxy_port}")
    print("=" * 60)

    start_time = time.monotonic()

    threads = []
    for i in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(args.proxy_port, args.url, per_thread, stats, i),
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    elapsed = time.monotonic() - start_time

    print(f"\n{'=' * 60}")
    print(f"Results ({elapsed:.1f}s elapsed):")
    print(f"  Total requests:   {stats.total}")
    print(f"  Successful:       {stats.success}")
    print(f"  Rate-limited:     {stats.rate_limited}")
    print(f"  Errors:           {stats.errors}")
    if stats.latencies:
        avg = sum(stats.latencies) / len(stats.latencies)
        print(f"  Avg latency:      {avg*1000:.0f} ms")
        print(f"  Requests/sec:     {stats.total / elapsed:.1f}")
    print(f"{'=' * 60}")

    if stats.rate_limited > 0:
        print("\nRate limiting IS working - server throttled requests.")
    else:
        print("\nNo rate limiting observed - try increasing --requests or --threads.")


if __name__ == "__main__":
    main()
