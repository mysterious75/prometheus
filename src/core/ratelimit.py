"""Rate Limiter — controls request speed to avoid overwhelming targets.

Prevents:
- Target server crashes
- WAF bans
- Legal issues from excessive traffic
- Noisy scans that get detected
"""

import time
import threading
from typing import Optional
from dataclasses import dataclass


@dataclass
class RateLimit:
    """Rate limit configuration."""
    requests_per_second: float = 10.0
    burst: int = 20  # max concurrent requests
    per_host: bool = True  # separate limit per host


class RateLimiter:
    """Token bucket rate limiter.

    Usage:
        limiter = RateLimiter(requests_per_second=10)
        limiter.acquire("example.com")  # blocks if rate exceeded
    """

    def __init__(self, requests_per_second: float = 10.0, burst: int = 20):
        self.rps = requests_per_second
        self.burst = burst
        self._buckets: dict = {}  # host -> (tokens, last_update)
        self._lock = threading.Lock()

    def acquire(self, host: str = "default") -> float:
        """Acquire a token. Returns wait time in seconds."""
        with self._lock:
            now = time.monotonic()
            if host not in self._buckets:
                self._buckets[host] = (float(self.burst), now)

            tokens, last_update = self._buckets[host]
            elapsed = now - last_update
            tokens = min(self.burst, tokens + elapsed * self.rps)

            if tokens >= 1.0:
                self._buckets[host] = (tokens - 1.0, now)
                return 0.0
            else:
                wait = (1.0 - tokens) / self.rps
                self._buckets[host] = (0.0, now + wait)
                return wait

    def wait(self, host: str = "default"):
        """Acquire a token, blocking if necessary."""
        wait_time = self.acquire(host)
        if wait_time > 0:
            time.sleep(wait_time)


# Default limiter: 10 req/sec
_default_limiter = RateLimiter(requests_per_second=10.0)


def get_limiter(rps: Optional[float] = None) -> RateLimiter:
    """Get rate limiter instance."""
    if rps is not None:
        return RateLimiter(requests_per_second=rps)
    return _default_limiter
