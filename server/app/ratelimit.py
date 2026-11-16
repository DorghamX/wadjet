"""Rate limiting for login attempts (section 13).

Implements a simple in-memory rate limiter with lockout backoff:
- Track failed attempts per username and IP
- After N failures within a window, lock out for a period
- Exponential backoff on repeated lockouts
"""

from __future__ import annotations

import time

# Configuration
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 300  # 5 minutes
BASE_LOCKOUT_SECONDS = 60  # 1 minute
MAX_LOCKOUT_SECONDS = 3600  # 1 hour


class LoginRateLimiter:
    """In-memory rate limiter for login attempts.

    Tracks failures per (username, ip) key and locks out after too many failures.
    Uses exponential backoff: 1st lockout = 1min, 2nd = 2min, 3rd = 4min, etc.
    """

    def __init__(self) -> None:
        # key -> list of failure timestamps (seconds since epoch)
        self._failures: dict[str, list[float]] = {}
        # key -> lockout_until (seconds since epoch)
        self._lockouts: dict[str, float] = {}

    def _key(self, username: str, ip: str) -> str:
        return f"{username.lower()}|{ip}"

    def is_locked_out(self, username: str, ip: str) -> float | None:
        """Check if the key is currently locked out.

        Returns:
            None if not locked out,
            seconds remaining if locked out.
        """
        key = self._key(username, ip)
        now = time.time()

        lockout_until = self._lockouts.get(key)
        if lockout_until and now < lockout_until:
            return lockout_until - now

        # Clean up old failures
        failures = self._failures.get(key, [])
        cutoff = now - FAILURE_WINDOW_SECONDS
        self._failures[key] = [f for f in failures if f > cutoff]

        return None

    def record_failure(self, username: str, ip: str) -> float | None:
        """Record a failed login attempt.

        Returns:
            None if the key is not yet locked out,
            seconds remaining if this failure triggered a lockout.
        """
        key = self._key(username, ip)
        now = time.time()

        # Clean old failures
        failures = self._failures.get(key, [])
        cutoff = now - FAILURE_WINDOW_SECONDS
        failures = [f for f in failures if f > cutoff]
        failures.append(now)
        self._failures[key] = failures

        if len(failures) >= MAX_FAILURES:
            # Calculate lockout duration with exponential backoff
            # Count recent lockouts in the window
            lockout_count = sum(
                1 for k, until in self._lockouts.items() if k == key and until > cutoff
            )
            lockout_seconds = min(
                BASE_LOCKOUT_SECONDS * (2**lockout_count),
                MAX_LOCKOUT_SECONDS,
            )
            lockout_until = now + lockout_seconds
            self._lockouts[key] = lockout_until
            # Reset failures after lockout
            self._failures[key] = []
            return float(lockout_seconds)

        return None

    def record_success(self, username: str, ip: str) -> None:
        """Record a successful login: clear failures and lockout for this key."""
        key = self._key(username, ip)
        self._failures.pop(key, None)
        self._lockouts.pop(key, None)

    def reset(self) -> None:
        """Clear all state (for tests)."""
        self._failures.clear()
        self._lockouts.clear()


# Singleton rate limiter instance
rate_limiter = LoginRateLimiter()
