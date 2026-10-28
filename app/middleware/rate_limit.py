"""IP-based rate limiting middleware."""
import ipaddress
import logging
import time
from collections import defaultdict
from threading import Lock

from fastapi import Request

from app.config import settings

logger = logging.getLogger(__name__)
_warned_misconfig = False


def get_client_ip(request: Request) -> str:
    """Return the client IP, trusting only what our own proxies appended.

    Each trusted proxy (AWS ALB, Cloudflare, nginx) appends the address it
    received the connection from to X-Forwarded-For, so the client is the
    entry `trusted_proxy_hops` from the right. Everything left of that was
    written by the client and is ignored: taking the first entry, as this
    function used to, let anyone pick their own rate-limit bucket.

    The header is only honoured when the connection itself comes from a
    private address (a proxy on our network). A public peer reached the app
    directly, so whatever it put in the header is its own invention.
    """
    peer = request.client.host if request.client else "unknown"
    hops = settings.trusted_proxy_hops
    if hops <= 0 or not _is_private_or_local(peer):
        return peer

    # A proxy may add its own header line rather than extend the client's.
    forwarded = [
        part.strip()
        for line in request.headers.getlist("x-forwarded-for")
        for part in line.split(",")
        if part.strip()
    ]
    if not forwarded:
        _warn_once(
            "Request from private peer %s carried no X-Forwarded-For; "
            "every client shares that peer's rate-limit bucket", peer
        )
        return peer

    # Fewer entries than proxies: every entry came from a proxy we trust.
    ip = _strip_port(forwarded[-hops] if len(forwarded) >= hops else forwarded[0])
    try:
        if ipaddress.ip_address(ip).is_private:
            _warn_once(
                "Client IP resolved to private address %s; TRUSTED_PROXY_HOPS=%d "
                "is probably lower than the number of proxies in front of the faucet",
                ip, hops,
            )
    except ValueError:
        return peer
    return ip


def _is_private_or_local(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        # Not an IP at all (a unix socket, or the test client): local.
        return True


def _strip_port(entry: str) -> str:
    """`1.2.3.4:5678` and `[2001:db8::1]:5678` → bare address."""
    if entry.startswith("["):
        return entry[1:entry.find("]")] if "]" in entry else entry
    if entry.count(":") == 1:
        return entry.split(":", 1)[0]
    return entry


def _warn_once(message: str, *args) -> None:
    global _warned_misconfig
    if not _warned_misconfig:
        _warned_misconfig = True
        logger.warning(message, *args)


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
