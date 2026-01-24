"""
Rate limiter for the Sleepyteepee plugin.

This module provides a sliding window rate limiter that tracks request
timestamps per IP address and enforces a maximum requests per minute limit.
"""
import time
from typing import Dict, List, Tuple
from threading import Lock


class RateLimiter:
    """Rate limiter using a sliding window algorithm.

    Tracks request timestamps per IP address and enforces a maximum
    requests per minute limit. Old entries are automatically cleaned up
    to prevent memory leaks.

    Attributes:
        max_requests: Maximum number of requests allowed per minute
        window_seconds: Time window in seconds (default: 60)
        _requests: Dictionary mapping IP addresses to request timestamps
        _lock: Thread lock for thread-safe operations
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        """Initialize the rate limiter.

        Args:
            max_requests: Maximum number of requests allowed per time window
            window_seconds: Time window in seconds (default: 60 for 1 minute)
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
        self._lock = Lock()

    def is_allowed(self, ip_address: str) -> Tuple[bool, int]:
        """Check if a request from the given IP is allowed.

        Args:
            ip_address: The client IP address

        Returns:
            A tuple of (allowed, retry_after) where:
            - allowed: True if request is allowed, False if rate limit exceeded
            - retry_after: Seconds until the next request is allowed (0 if allowed)
        """
        current_time = time.time()

        with self._lock:
            # Get existing timestamps for this IP, or create new list
            timestamps = self._requests.get(ip_address, [])

            # Filter out timestamps outside the window (cleanup old entries)
            window_start = current_time - self.window_seconds
            timestamps = [ts for ts in timestamps if ts > window_start]

            # Check if rate limit is exceeded
            if len(timestamps) >= self.max_requests:
                # Calculate retry_after based on oldest timestamp in window
                oldest_timestamp = timestamps[0]
                retry_after = int(oldest_timestamp + self.window_seconds - current_time) + 1
                return False, max(0, retry_after)

            # Add current timestamp and update storage
            timestamps.append(current_time)
            self._requests[ip_address] = timestamps

            return True, 0

    def cleanup_old_entries(self, age_seconds: int = 300) -> None:
        """Clean up entries older than the specified age.

        This method should be called periodically to prevent memory leaks.
        The default age of 300 seconds (5 minutes) provides a reasonable
        balance between memory usage and rate limiting effectiveness.

        Args:
            age_seconds: Remove entries older than this many seconds
        """
        current_time = time.time()
        cutoff_time = current_time - age_seconds

        with self._lock:
            # Find IPs with all timestamps older than cutoff
            ips_to_remove = []
            for ip, timestamps in self._requests.items():
                # Remove old timestamps
                self._requests[ip] = [ts for ts in timestamps if ts > cutoff_time]
                # Mark IP for removal if no timestamps remain
                if not self._requests[ip]:
                    ips_to_remove.append(ip)

            # Remove empty IP entries
            for ip in ips_to_remove:
                del self._requests[ip]

    def get_stats(self) -> Dict[str, any]:
        """Get statistics about the rate limiter.

        Returns:
            Dictionary with statistics including total tracked IPs and
            total tracked requests
        """
        with self._lock:
            total_requests = sum(len(timestamps) for timestamps in self._requests.values())
            return {
                'tracked_ips': len(self._requests),
                'total_requests': total_requests,
                'max_requests': self.max_requests,
                'window_seconds': self.window_seconds,
            }

    def reset(self) -> None:
        """Reset all rate limiting data.

        This clears all tracked IP addresses and their request history.
        """
        with self._lock:
            self._requests.clear()
