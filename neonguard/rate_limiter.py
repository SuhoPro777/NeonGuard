"""
NeonGuard Rate Limiter
======================
Token-bucket based rate limiting per IP address.
Thread-safe, in-memory, zero-dependency.
"""

import threading
import time
import logging
from typing import Dict, Any

logger = logging.getLogger("neonguard.rate_limiter")

_DEFAULT_RPM = 60


class RateLimiter:
    """
    Token-bucket rate limiter per IP address.

    Example:
        >>> limiter = RateLimiter()
        >>> limiter.set_limit("192.168.1.1", rpm=30)
        >>> result = limiter.check("192.168.1.1")
        >>> print(result['allowed'])  # True / False
    """

    def __init__(self, default_rpm: int = _DEFAULT_RPM):
        self._default_rpm = default_rpm
        self._buckets: Dict[str, "_Bucket"] = {}
        self._limits: Dict[str, int] = {}
        self._lock = threading.Lock()

    def set_limit(self, ip: str, rpm: int) -> None:
        """Set max requests per minute for an IP."""
        with self._lock:
            self._limits[ip] = rpm
            self._buckets[ip] = _Bucket(rpm)
        logger.debug(f"Rate limit set: {ip} = {rpm} rpm")

    def check(self, ip: str) -> Dict[str, Any]:
        """
        Check if an IP is allowed to make a request.

        Returns:
            {
                'allowed': bool,
                'remaining': int,
                'reset_in': float,  # seconds until bucket refills
                'limit': int,
            }
        """
        with self._lock:
            if ip not in self._buckets:
                # Auto-create bucket with default limit
                rpm = self._limits.get(ip, self._default_rpm)
                self._buckets[ip] = _Bucket(rpm)

            bucket = self._buckets[ip]
            allowed = bucket.consume()

            return {
                "allowed": allowed,
                "remaining": int(bucket.tokens),
                "reset_in": round(bucket.time_to_refill(), 2),
                "limit": bucket.capacity,
            }

    def reset(self, ip: str) -> None:
        """Reset the bucket for an IP (e.g., after manual review)."""
        with self._lock:
            if ip in self._buckets:
                rpm = self._limits.get(ip, self._default_rpm)
                self._buckets[ip] = _Bucket(rpm)

    def limited_count(self) -> int:
        """Return number of IPs with custom limits."""
        return len(self._limits)

    def get_stats(self) -> Dict[str, Dict]:
        """Return stats for all tracked IPs."""
        with self._lock:
            stats = {}
            for ip, bucket in self._buckets.items():
                stats[ip] = {
                    "limit_rpm": bucket.capacity,
                    "tokens_remaining": round(bucket.tokens, 1),
                    "is_limited": bucket.tokens < 1,
                }
            return stats


class _Bucket:
    """Token bucket implementation."""

    def __init__(self, rpm: int):
        self.capacity = float(rpm)
        self.tokens = float(rpm)
        self.refill_rate = rpm / 60.0  # tokens per second
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        added = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + added)
        self.last_refill = now

    def consume(self) -> bool:
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def time_to_refill(self) -> float:
        """Seconds until at least 1 token is available."""
        self._refill()
        if self.tokens >= 1.0:
            return 0.0
        deficit = 1.0 - self.tokens
        return deficit / self.refill_rate
