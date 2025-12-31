"""IP-based rate limiting middleware."""
import time
from collections import defaultdict
from threading import Lock

from app.config import settings


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
