"""
SecureVault Rate Limiter Module

This module implements brute force protection for authentication attempts:
- Tracks failed login attempts per user
- Applies exponential backoff delays
- Implements account lockout after threshold
- Provides time-based lockout release

Security Features:
- Exponential backoff: 1s, 2s, 4s, 8s, 16s...
- Account lockout after 5 failed attempts (configurable)
- 30-minute lockout duration (configurable)
- Prevents timing-based user enumeration
"""

import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict
from dataclasses import dataclass

from auth_database import AuthDatabase

logger = logging.getLogger(__name__)


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    max_attempts: int = 5                    # Maximum failed attempts before lockout
    lockout_duration_minutes: int = 30       # Lockout duration
    exponential_backoff: bool = True         # Use exponential backoff
    base_delay_seconds: float = 1.0          # Base delay for exponential backoff
    max_delay_seconds: float = 60.0          # Maximum delay cap
    max_global_attempts: int = 20            # Failed attempts across the device window
    global_window_seconds: int = 300         # Window size for device-level rate limiting
    max_email_attempts: int = 8              # Failed attempts per email hash
    email_window_seconds: int = 120          # Window size for per-email throttling


class RateLimitError(Exception):
    """Raised when rate limit is exceeded"""
    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after  # Seconds until retry allowed


class AccountLockedError(RateLimitError):
    """Raised when account is locked due to too many failed attempts"""
    pass


class RateLimiter:
    """
    Rate limiter for authentication attempts.

    Implements brute force protection through:
    1. Failed attempt tracking
    2. Exponential backoff delays
    3. Account lockout after threshold
    4. Time-based auto-unlock

    The rate limiter works with the AuthDatabase to track and enforce
    authentication attempt limits.
    """

    def __init__(
        self,
        db: AuthDatabase,
        config: Optional[RateLimitConfig] = None
    ):
        """
        Initialize rate limiter.

        Args:
            db: Authentication database
            config: Rate limit configuration (uses defaults if None)
        """
        self.db = db
        self.config = config or RateLimitConfig()

        # In-memory cache for last attempt times (to implement backoff)
        self._last_attempt_time: Dict[int, float] = {}
        self._lock = threading.Lock()

    def check_rate_limit(self, user_id: int) -> None:
        """
        Check if user can attempt authentication.

        Args:
            user_id: User ID to check

        Raises:
            AccountLockedError: Account is locked
            RateLimitError: Must wait before next attempt (exponential backoff)
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Check if account is locked
        if self.db.is_account_locked(user_id):
            if user.lockout_until:
                retry_after = (user.lockout_until - datetime.now()).total_seconds()
                if retry_after > 0:
                    raise AccountLockedError(
                        f"Account locked due to too many failed attempts. "
                        f"Try again in {int(retry_after / 60)} minutes.",
                        retry_after=retry_after
                    )
                else:
                    # Lockout expired, auto-unlock
                    self.db.unlock_account(user_id)
                    logger.info(f"Auto-unlocked account {user_id} after lockout expiration")
            else:
                raise AccountLockedError("Account is locked. Contact administrator.")

        # Check exponential backoff
        if self.config.exponential_backoff and user.failed_attempts > 0:
            required_delay = self._calculate_backoff_delay(user.failed_attempts)

            # Check last attempt time
            last_attempt = self._get_last_attempt_time(user_id)
            time_since_last = time.time() - last_attempt

            if time_since_last < required_delay:
                retry_after = required_delay - time_since_last
                raise RateLimitError(
                    f"Too many failed attempts. Please wait {int(retry_after)} seconds before trying again.",
                    retry_after=retry_after
                )

    def check_global_rate_limit(self, email_hash: Optional[bytes]) -> None:
        """Enforce device-level and per-email throttles."""

        self._enforce_window_limit(
            email_hash=None,
            max_attempts=self.config.max_global_attempts,
            window_seconds=self.config.global_window_seconds,
            scope="device",
        )

        if email_hash is not None:
            self._enforce_window_limit(
                email_hash=email_hash,
                max_attempts=self.config.max_email_attempts,
                window_seconds=self.config.email_window_seconds,
                scope="account",
            )

    def record_failed_attempt(self, user_id: int) -> None:
        """
        Record a failed authentication attempt.

        This increments the failure counter and may lock the account if
        the threshold is exceeded.

        Args:
            user_id: User ID
        """
        # Increment failed attempts counter
        failed_count = self.db.increment_failed_attempts(user_id)

        # Record attempt time for exponential backoff
        timestamp = time.time()
        self._set_last_attempt_time(user_id, timestamp)

        logger.warning(
            f"Failed authentication attempt for user {user_id}. "
            f"Total failures: {failed_count}/{self.config.max_attempts}"
        )

        # Check if we should lock the account
        if failed_count >= self.config.max_attempts:
            self.db.lock_account(user_id, self.config.lockout_duration_minutes)
            logger.warning(
                f"Account {user_id} locked after {failed_count} failed attempts. "
                f"Lockout duration: {self.config.lockout_duration_minutes} minutes"
            )

    def record_successful_attempt(self, user_id: int) -> None:
        """
        Record a successful authentication attempt.

        This resets the failure counter and removes any lockout.

        Args:
            user_id: User ID
        """
        self.db.reset_failed_attempts(user_id)

        # Clear backoff timer
        self._clear_last_attempt_time(user_id)

        logger.info(f"Successful authentication for user {user_id}. Reset failure counter.")

    def _calculate_backoff_delay(self, failed_attempts: int) -> float:
        """
        Calculate exponential backoff delay.

        Formula: base_delay * 2^(failed_attempts - 1)
        Capped at max_delay_seconds.

        Args:
            failed_attempts: Number of failed attempts

        Returns:
            Delay in seconds
        """
        if failed_attempts <= 0:
            return 0.0

        # Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s (capped)
        delay = self.config.base_delay_seconds * (2 ** (failed_attempts - 1))

        # Cap at maximum delay
        return min(delay, self.config.max_delay_seconds)

    def _enforce_window_limit(
        self,
        email_hash: Optional[bytes],
        max_attempts: int,
        window_seconds: int,
        scope: str,
    ) -> None:
        if max_attempts <= 0 or window_seconds <= 0:
            return

        window_start = datetime.now() - timedelta(seconds=window_seconds)
        attempts = self.db.get_failed_attempts_since(window_start, email_hash=email_hash)

        if len(attempts) < max_attempts:
            return

        oldest = attempts[0]
        if not oldest.timestamp:
            raise RateLimitError(
                "Too many authentication failures. Please wait before trying again."
            )

        retry_after = window_seconds - (datetime.now() - oldest.timestamp).total_seconds()
        retry_after = max(1.0, retry_after)

        if scope == "device":
            message = "Too many failed attempts on this device. Please wait before trying again."
        else:
            message = "Too many failed attempts for this account. Please wait before trying again."

        raise RateLimitError(message, retry_after=retry_after)

    def is_locked(self, user_id: int) -> bool:
        """
        Check if account is currently locked.

        Args:
            user_id: User ID

        Returns:
            True if account is locked, False otherwise
        """
        return self.db.is_account_locked(user_id)

    def unlock_account(self, user_id: int) -> None:
        """
        Manually unlock account (admin function).

        This resets the failure counter and removes the lockout.

        Args:
            user_id: User ID to unlock
        """
        self.db.unlock_account(user_id)

        # Clear backoff timer
        self._clear_last_attempt_time(user_id)

        logger.info(f"Manually unlocked account {user_id}")

    def get_lockout_status(self, user_id: int) -> Dict[str, any]:
        """
        Get detailed lockout status for user.

        Args:
            user_id: User ID

        Returns:
            Dictionary with lockout status:
            - is_locked: bool
            - failed_attempts: int
            - max_attempts: int
            - lockout_until: datetime (if locked)
            - retry_after_seconds: float (if rate limited)
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        status = {
            'is_locked': user.is_locked,
            'failed_attempts': user.failed_attempts,
            'max_attempts': self.config.max_attempts,
            'lockout_until': user.lockout_until,
            'retry_after_seconds': 0.0
        }

        # Calculate retry delay if applicable
        if user.is_locked and user.lockout_until:
            retry_after = (user.lockout_until - datetime.now()).total_seconds()
            status['retry_after_seconds'] = max(0.0, retry_after)
        elif user.failed_attempts > 0 and self.config.exponential_backoff:
            required_delay = self._calculate_backoff_delay(user.failed_attempts)
            last_attempt = self._get_last_attempt_time(user_id)
            time_since_last = time.time() - last_attempt
            retry_after = max(0.0, required_delay - time_since_last)
            status['retry_after_seconds'] = retry_after

        return status

    def _get_last_attempt_time(self, user_id: int) -> float:
        """Retrieve the last attempt timestamp for a user."""
        with self._lock:
            return self._last_attempt_time.get(user_id, 0.0)

    def _set_last_attempt_time(self, user_id: int, timestamp: float) -> None:
        """Store the last attempt timestamp for a user."""
        with self._lock:
            self._last_attempt_time[user_id] = timestamp

    def _clear_last_attempt_time(self, user_id: int) -> None:
        """Remove any cached attempt timestamp for a user."""
        with self._lock:
            self._last_attempt_time.pop(user_id, None)

    def get_remaining_attempts(self, user_id: int) -> int:
        """
        Get number of remaining attempts before lockout.

        Args:
            user_id: User ID

        Returns:
            Number of attempts remaining (0 if locked)
        """
        user = self.db.get_user_by_id(user_id)
        if not user:
            return 0

        if user.is_locked:
            return 0

        return max(0, self.config.max_attempts - user.failed_attempts)

    def reset_all_lockouts(self) -> int:
        """
        Reset all expired lockouts (maintenance function).

        This should be called periodically to clean up expired lockouts.

        Returns:
            Number of accounts unlocked
        """
        # This would need to be implemented with a database query
        # For now, we'll skip it as it requires iterating all users
        logger.info("reset_all_lockouts() called - not yet implemented")
        return 0


# Convenience functions

def check_rate_limit(db: AuthDatabase, user_id: int) -> None:
    """Check rate limit (convenience wrapper)"""
    limiter = RateLimiter(db)
    limiter.check_rate_limit(user_id)


def record_failed_attempt(db: AuthDatabase, user_id: int) -> None:
    """Record failed attempt (convenience wrapper)"""
    limiter = RateLimiter(db)
    limiter.record_failed_attempt(user_id)


def record_successful_attempt(db: AuthDatabase, user_id: int) -> None:
    """Record successful attempt (convenience wrapper)"""
    limiter = RateLimiter(db)
    limiter.record_successful_attempt(user_id)
