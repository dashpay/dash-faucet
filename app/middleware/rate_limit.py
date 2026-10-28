"""IP-based rate limiting middleware."""
import ipaddress
import logging
import time
from collections import defaultdict
from threading import Lock

from fastapi import Request

from app.config import settings

logger = logging.getLogger(__name__)
_warned_private_ip = False


def get_client_ip(request: Request) -> str:
    """Return the client IP, trusting only what our own proxies appended.

    Each trusted proxy (AWS ALB, Cloudflare, nginx) appends the address it
    received the connection from to X-Forwarded-For, so the client is the
    entry `trusted_proxy_hops` from the right. Everything left of that was
    written by the client and is ignored: taking the first entry, as this
    function used to, let anyone pick their own rate-limit bucket.
    """
    peer = request.client.host if request.client else "unknown"
    hops = settings.trusted_proxy_hops
    if hops <= 0:
        return peer

    forwarded = [
        part.strip()
        for part in request.headers.get("X-Forwarded-For", "").split(",")
        if part.strip()
    ]
    if not forwarded:
        return peer

    # Fewer entries than proxies: every entry came from a proxy we trust.
    ip = forwarded[-hops] if len(forwarded) >= hops else forwarded[0]
    _warn_if_private(ip)
    return ip


def _warn_if_private(ip: str) -> None:
    """Log once if the resolved client looks like one of our own proxies."""
    global _warned_private_ip
    if _warned_private_ip:
        return
    try:
        private = ipaddress.ip_address(ip).is_private
    except ValueError:
        return
    if private:
        _warned_private_ip = True
        logger.warning(
            "Client IP resolved to private address %s; TRUSTED_PROXY_HOPS=%d "
            "is probably lower than the number of proxies in front of the faucet",
            ip,
            settings.trusted_proxy_hops,
        )


def normalize_ip(ip: str) -> str:
    """Normalize IP address for rate limiting.

    IPv4: use as-is
    IPv6: truncate to /48 prefix (users typically have /48 or /64 blocks)
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv6Address):
            # Truncate to /48 network
            network = ipaddress.IPv6Network((addr, 48), strict=False)
            return str(network.network_address)
        return ip
    except ValueError:
        # Invalid IP, return as-is
        return ip


class RateLimiter:
    """Simple in-memory IP-based rate limiter."""

    def __init__(self, max_requests: int | None = None, window_seconds: int = 3600):
        """Initialize the rate limiter.

        Args:
            max_requests: Maximum requests per IP per window (default from settings)
            window_seconds: Time window in seconds (default 1 hour)
        """
        self.max_requests = max_requests or settings.rate_limit_per_hour
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def _cleanup_old_requests(self, ip: str, current_time: float) -> None:
        """Remove requests older than the time window."""
        cutoff = current_time - self.window_seconds
        self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]

    def is_allowed(self, ip: str) -> tuple[bool, int]:
        """Check if a request from an IP is allowed.

        Args:
            ip: The client IP address

        Returns:
            Tuple of (is_allowed, seconds_until_reset)
        """
        ip = normalize_ip(ip)
        current_time = time.time()

        with self._lock:
            self._cleanup_old_requests(ip, current_time)

            if len(self._requests[ip]) >= self.max_requests:
                # Calculate when the oldest request will expire
                oldest = min(self._requests[ip])
                retry_after = int(oldest + self.window_seconds - current_time) + 1
                return False, max(1, retry_after)

            return True, 0

    def record_request(self, ip: str) -> None:
        """Record a request from an IP.

        Args:
            ip: The client IP address
        """
        ip = normalize_ip(ip)
        current_time = time.time()

        with self._lock:
            self._cleanup_old_requests(ip, current_time)
            self._requests[ip].append(current_time)

    def get_remaining(self, ip: str) -> int:
        """Get the number of remaining requests for an IP.

        Args:
            ip: The client IP address

        Returns:
            Number of remaining requests in the current window
        """
        ip = normalize_ip(ip)
        current_time = time.time()

        with self._lock:
            self._cleanup_old_requests(ip, current_time)
            return max(0, self.max_requests - len(self._requests[ip]))

    def cleanup_all(self) -> None:
        """Remove all expired entries from all IPs."""
        current_time = time.time()

        with self._lock:
            empty_ips = []
            for ip in self._requests:
                self._cleanup_old_requests(ip, current_time)
                if not self._requests[ip]:
                    empty_ips.append(ip)

            for ip in empty_ips:
                del self._requests[ip]


# Global rate limiter instance
rate_limiter = RateLimiter()
