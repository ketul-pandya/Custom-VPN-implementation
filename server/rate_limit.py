"""
rate_limit.py — Token-bucket rate limiter + connection management.

Features:
  - Per-IP request rate limiting (token bucket).
  - Per-IP concurrent connection cap.
  - Global concurrent connection cap.
  - Idle-timeout tracking (caller is responsible for disconnecting).
"""

import logging
import threading
import time

logger = logging.getLogger("vpn.rate_limit")


class TokenBucket:
    """Classic token-bucket rate limiter for a single key (e.g. IP)."""

    def __init__(self, rate: float, capacity: int):
        """
        Args:
            rate: tokens added per second.
            capacity: maximum burst size.
        """
        self.rate = rate
        self.capacity = capacity
        self._tokens = float(capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Try to consume *tokens*.  Returns True if allowed."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._last = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False


class RateLimiter:
    """Per-IP rate limiting + connection caps."""

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst: int = 20,
        max_connections_per_ip: int = 5,
        max_total_connections: int = 50,
        idle_timeout: float = 300.0,
    ):
        self.rps = requests_per_second
        self.burst = burst
        self.max_per_ip = max_connections_per_ip
        self.max_total = max_total_connections
        self.idle_timeout = idle_timeout

        self._buckets: dict[str, TokenBucket] = {}
        self._connections: dict[str, int] = {}   # ip → active count
        self._total_connections = 0
        self._last_activity: dict[str, float] = {}  # ip → monotonic timestamp
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Rate-check
    # ------------------------------------------------------------------
    def check_rate(self, ip: str) -> bool:
        """Return True if the request from *ip* is allowed (not rate-limited).

        Creates a bucket on first access.
        """
        with self._lock:
            if ip not in self._buckets:
                self._buckets[ip] = TokenBucket(self.rps, self.burst)
            bucket = self._buckets[ip]

        allowed = bucket.consume()
        if not allowed:
            logger.info("RATE_LIMITED  ip=%s", ip)
        return allowed

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------
    def try_add_connection(self, ip: str) -> bool:
        """Try to register a new connection from *ip*.

        Returns True if the connection is allowed; False if either the
        per-IP or global cap is exceeded.
        """
        with self._lock:
            if self._total_connections >= self.max_total:
                logger.info(
                    "CONN_REJECTED  ip=%s  reason=global_cap (%d/%d)",
                    ip, self._total_connections, self.max_total,
                )
                return False

            current = self._connections.get(ip, 0)
            if current >= self.max_per_ip:
                logger.info(
                    "CONN_REJECTED  ip=%s  reason=per_ip_cap (%d/%d)",
                    ip, current, self.max_per_ip,
                )
                return False

            self._connections[ip] = current + 1
            self._total_connections += 1
            self._last_activity[ip] = time.monotonic()
            logger.debug(
                "CONN_ADDED  ip=%s  per_ip=%d  total=%d",
                ip, self._connections[ip], self._total_connections,
            )
            return True

    def remove_connection(self, ip: str) -> None:
        """Unregister a connection from *ip*."""
        with self._lock:
            current = self._connections.get(ip, 0)
            if current > 0:
                self._connections[ip] = current - 1
                self._total_connections = max(0, self._total_connections - 1)
            if self._connections.get(ip) == 0:
                self._connections.pop(ip, None)
            logger.debug(
                "CONN_REMOVED  ip=%s  total=%d", ip, self._total_connections,
            )

    # ------------------------------------------------------------------
    # Idle tracking
    # ------------------------------------------------------------------
    def touch(self, ip: str) -> None:
        """Update last-activity timestamp for *ip*."""
        with self._lock:
            self._last_activity[ip] = time.monotonic()

    def is_idle(self, ip: str) -> bool:
        """Return True if *ip* has been idle longer than ``idle_timeout``."""
        with self._lock:
            last = self._last_activity.get(ip)
            if last is None:
                return True
            return (time.monotonic() - last) > self.idle_timeout

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    @property
    def total_connections(self) -> int:
        with self._lock:
            return self._total_connections

    def connections_for(self, ip: str) -> int:
        with self._lock:
            return self._connections.get(ip, 0)
