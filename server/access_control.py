"""
access_control.py — IP whitelisting for the VPN server.

Supports individual IPs and CIDR notation.  Loads from a text file with
one entry per line; blank lines and ``#`` comments are ignored.
"""

import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger("vpn.access_control")


class AccessController:
    """IP-based whitelist."""

    def __init__(self, whitelist_path: str | Path | None = None):
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._path = Path(whitelist_path) if whitelist_path else None
        if self._path:
            self.reload()

    # ------------------------------------------------------------------
    def reload(self) -> None:
        """(Re-)load the whitelist file."""
        if not self._path or not self._path.exists():
            logger.warning("Whitelist file not found: %s — allowing all", self._path)
            self._networks = []
            return

        networks = []
        for lineno, raw in enumerate(self._path.read_text().splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError as e:
                logger.warning("Whitelist line %d invalid: %s (%s)", lineno, line, e)

        self._networks = networks
        logger.info(
            "Loaded %d whitelist entries from %s", len(networks), self._path,
        )

    # ------------------------------------------------------------------
    def is_allowed(self, ip: str) -> bool:
        """Return True if *ip* matches a whitelisted network.

        If the whitelist is empty (no file or empty file) **all** IPs are
        allowed — so the server works out-of-the-box for demos.
        """
        if not self._networks:
            return True  # no whitelist loaded → open

        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning("Invalid IP address: %s", ip)
            return False

        for net in self._networks:
            if addr in net:
                return True

        logger.info("BLOCKED  ip=%s  (not in whitelist)", ip)
        return False
