"""
SecureVault Authentication Manager Module

This is the main authentication coordinator that ties together all authentication
components:
- User authentication with PIN
- Password-based authentication (for recovery)
- Session management
- Rate limiting
- Audit logging

This module provides the high-level authentication API used by the GUI and CLI.
"""

import ctypes
import os
import uuid
import logging
from typing import Optional, Dict, Any, Union, List
import threading
from collections import defaultdict
from typing import Optional, Dict, Union, DefaultDict
import warnings
from contextlib import contextmanager
from typing import Optional, Dict, Any, Union, Iterator
from typing import Optional, Dict, Any, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from threading import Lock

from auth_database import AuthDatabase, Session, User
from access_control import AccessControl, PermissionLevel
from user_manager import UserManager
from pin_manager import PINManager
from rate_limiter import RateLimiter, RateLimitError, AccountLockedError
from secure_memory import secure_alloc, secure_free, secure_wipe
from instance_guard import TamperDetectedError
from auth_queue import AuthQueue
from audit_logger import AuditEventType, AuditSeverity, get_audit_logger

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration"""
    session_timeout_minutes: int = 30      # Session expires after 30 minutes
    session_idle_timeout_minutes: int = 15  # Auto-logout after 15 minutes idle
    max_concurrent_sessions: int = 1        # Only one session per user
    argon_concurrency_limit: int = 2        # Max concurrent Argon2 operations
    argon_wait_warning_seconds: float = 1.0
    argon_metrics_log_interval: int = 50


class AuthenticationError(Exception):
    """Base class for authentication errors"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Raised when credentials are invalid"""
    pass


class SessionExpiredError(AuthenticationError):
    """Raised when session has expired"""
    pass


class SystemLockdownError(AuthenticationError):
    """Raised when the authentication subsystem has been locked down."""
    pass


class SessionSecret:
    """Secure container that stores session secrets in locked memory."""

    def __init__(self, secret: Union[bytes, bytearray, memoryview]):
        buffer = bytearray(secret)
        self._length = len(buffer)
        self._memory = secure_alloc(self._length) if self._length else None

        if self._memory is not None and self._length:
            dest = (ctypes.c_ubyte * self._length).from_address(self._memory.address)
            dest[: self._length] = buffer

        if buffer:
            secure_wipe(buffer)

    def is_available(self) -> bool:
        return self._memory is not None and self._length > 0

    @contextmanager
    def access(self) -> Iterator[bytearray]:
        """Provide temporary access to the secret as a mutable buffer."""

        if not self.is_available():
            raise SessionExpiredError("Session secret is no longer available")

        temp = bytearray(self._length)
        if self._length:
            dest = (ctypes.c_ubyte * self._length).from_buffer(temp)
            ctypes.memmove(ctypes.addressof(dest), self._memory.address, self._length)

        try:
            yield temp
        finally:
            if temp:
                secure_wipe(temp)

    def zeroize(self) -> None:
        """Zeroize and release the underlying secure memory."""

        if self._memory is not None:
            self._memory.zero()
            secure_free(self._memory)
            self._memory = None

        self._length = 0

    def __del__(self):
        try:
            self.zeroize()
        except Exception:
            pass
class SessionHijackingError(AuthenticationError):
    """Raised when session client metadata does not match expectations."""


class AuthSession:
    """
    Active authentication session.

    Holds the decrypted master vault key in memory for the duration
    of the session. The master key is wiped from memory when the session ends.
    """

    def __init__(
        self,
        session_id: str,
        user_id: int,
        master_key: Union[bytes, bytearray],
        created_at: datetime,
        expires_at: datetime,
        lock: Optional[threading.Lock] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ):
        """
        Initialize authentication session.

        Args:
            session_id: Unique session identifier
            user_id: User ID
            master_key: Decrypted master vault key (stored in memory)
            created_at: Session creation time
            expires_at: Session expiration time
        """
        self.session_id = session_id
        self.user_id = user_id
        self._secret = SessionSecret(master_key)
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_activity = datetime.now()
        self._lock = lock or threading.Lock()
        self._lock: Lock = Lock()
        self.ip_address = ip_address
        self.user_agent = user_agent

    @contextmanager
    def master_key(self) -> Iterator[bytearray]:
        """Context manager providing temporary access to the master key."""

        Raises:
            SessionExpiredError: If session has expired
        """
        with self._lock:
            if self.is_expired():
                raise SessionExpiredError("Session has expired")

            if self._master_key is None:
                raise SessionExpiredError("Session has ended")

            self.last_activity = datetime.now()
            return bytes(self._master_key)
        now = datetime.now()
        if now >= self.expires_at:
            raise SessionExpiredError("Session has expired")

        with self._lock:
            now = datetime.now()
            if now >= self.expires_at:
                raise SessionExpiredError("Session has expired")

            if self._master_key is None:
                raise SessionExpiredError("Session is closed")

            self.last_activity = now
            return bytes(self._master_key)
        if self.is_expired():
            raise SessionExpiredError("Session has expired")

        if self._secret is None or not self._secret.is_available():
            raise SessionExpiredError("Session secret is no longer available")

        self.last_activity = datetime.now()

        with self._secret.access() as buffer:
            yield buffer

    def get_master_key(self) -> bytes:
        """Return the master key bytes (deprecated: use master_key())."""

        warnings.warn(
            "AuthSession.get_master_key() is deprecated; use the master_key() context"
            " manager instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        with self.master_key() as buffer:
            return bytes(buffer)

    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.now() >= self.expires_at

    def close(self):
        """Close session and wipe master key from memory"""
        with self._lock:
            if self._master_key:
                secure_wipe(self._master_key)
                self._master_key = None
        if self._secret is not None:
            self._secret.zeroize()
            self._secret = None

    def __del__(self):
        """Ensure master key is wiped when session is garbage collected"""
        self.close()

    def has_master_key(self) -> bool:
        """Return True if the session still retains a master key."""

        return self._secret is not None and self._secret.is_available()


class AuthManager:
    """
    Main authentication manager.

    Coordinates all authentication operations:
    - PIN-based login
    - Password-based login (recovery)
    - Session creation and validation
    - Logout
    - Rate limiting
    - Audit logging
    """

    def __init__(
        self,
        db: Optional[AuthDatabase] = None,
        config: Optional[AuthConfig] = None,
        auth_queue: Optional[AuthQueue] = None
    ):
        """
        Initialize authentication manager.

        Args:
            db: Authentication database (creates new if None)
            config: Authentication configuration (uses defaults if None)
        """
        if db is not None:
            self.db = db
        else:
            try:
                self.db = AuthDatabase()
            except TamperDetectedError as exc:
                raise SystemLockdownError(str(exc)) from exc
        self.config = config or AuthConfig()

        # Initialize sub-managers
        self.user_manager = UserManager(self.db)
        self.pin_manager = PINManager()
        self.rate_limiter = RateLimiter(self.db)
        self.auth_queue = auth_queue or AuthQueue(
            max_concurrent=self.config.argon_concurrency_limit,
            wait_warning_threshold=self.config.argon_wait_warning_seconds,
            metrics_log_interval=self.config.argon_metrics_log_interval,
        )

        # Active sessions (in-memory)
        self._sessions: Dict[str, AuthSession] = {}
        self._session_locks: DefaultDict[str, threading.Lock] = defaultdict(threading.Lock)

        # Access control service shared across the application
        self.access_control = AccessControl()

        logger.info("Authentication manager initialized")

    def authenticate_with_pin(
        self,
        email: str,
        pin: str,
        ip_address: Optional[str] = None,
        *,
        device_fingerprint: Optional[str] = None,
        user_agent: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuthSession:
        """
        Authenticate user with email + PIN.

        This is the primary authentication method for SecureVault.

        Process:
        1. Look up user by email
        2. Check rate limiting
        3. Retrieve PIN salt and encrypted master key
        4. Derive key from PIN
        5. Attempt to decrypt master key
        6. Verify master key with verification marker
        7. Create session
        8. Update login timestamp

        Args:
            email: User's email address
            pin: User's PIN
            ip_address: IP address of login attempt (for logging)
            device_fingerprint: Stable device identifier, if available
            user_agent: Client user agent string, if available
            user_agent: User agent string of the client initiating login

        Returns:
            AuthSession with decrypted master key

        Raises:
            InvalidCredentialsError: Email or PIN is incorrect
            AccountLockedError: Account is locked due to failed attempts
            RateLimitError: Too many attempts, must wait
        """
        email_lookup_hash = self.pin_manager.hash_email_for_lookup(email)

        attempt_context = self.rate_limiter.build_attempt_context(
            email=email,
            email_hash=email_lookup_hash,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
        )

        try:
            self.rate_limiter.check_global_rate_limit(attempt_context)
        except RateLimitError:
            self.db.record_auth_attempt(
                user_id=None,
                email_hash=email_lookup_hash,
                success=False,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason='device_rate_limited',
                normalized_email_hash=attempt_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=attempt_context.attempt_key,
            )
            raise

        # Get user by email
        user = self.user_manager.get_user_by_email(email)
        if not user:
            # Don't reveal that user doesn't exist
            # Record attempt with email hash for tracking
            self.db.record_auth_attempt(
                user_id=None,
                email_hash=email_lookup_hash,
                success=False,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason='invalid_email',
                normalized_email_hash=attempt_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=attempt_context.attempt_key,
            )
            self.rate_limiter.record_device_attempt(False, attempt_context)
            raise InvalidCredentialsError("Invalid email or PIN")

        user_context = self.rate_limiter.build_attempt_context(
            email=email,
            email_hash=user.email_lookup_hash or user.email_hash,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
        )

        try:
            # Check rate limiting
            self.rate_limiter.check_rate_limit(user.user_id)

        except (RateLimitError, AccountLockedError) as e:
            # Record locked/rate-limited attempt
            self.db.record_auth_attempt(
                user_id=user.user_id,
                email_hash=user.email_lookup_hash or user.email_hash,
                success=False,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason='rate_limited' if isinstance(e, RateLimitError) else 'account_locked',
                normalized_email_hash=user_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=user_context.attempt_key,
            )
            self.rate_limiter.record_device_attempt(False, user_context)
            raise

        # Get auth credentials
        credentials = self.db.get_credentials(user.user_id)
        if not credentials:
            logger.error(f"No credentials found for user {user.user_id}")
            raise InvalidCredentialsError("Invalid email or PIN")

        try:
            # Derive key from PIN
            with self.auth_queue.acquire("pin_derive"):
                pin_derived_key = self.pin_manager.derive_key_from_pin(
                    pin,
                    credentials.pin_salt,
                    algorithm=credentials.kdf_algorithm,
                    metadata=credentials.kdf_metadata,
                )

            # Attempt to decrypt master key
            associated_data = user.email_hash + b"master_key"
            try:
                master_key = self.pin_manager.decrypt_master_key(
                    credentials.encrypted_master_key,
                    pin_derived_key,
                    associated_data
                )
            except Exception as e:
                # PIN is incorrect - decryption failed
                self.rate_limiter.record_failed_attempt(user.user_id)

                self.db.record_auth_attempt(
                    user_id=user.user_id,
                    email_hash=user.email_lookup_hash or user.email_hash,
                    success=False,
                    attempt_type='pin',
                    ip_address=ip_address,
                    failure_reason='invalid_pin',
                    normalized_email_hash=user_context.normalized_email_hash,
                    user_agent=user_agent,
                    device_fingerprint=device_fingerprint,
                    attempt_key=user_context.attempt_key,
                )

                logger.warning(f"Failed PIN authentication for user {user.user_id}")
                self.rate_limiter.record_device_attempt(False, user_context)
                raise InvalidCredentialsError("Invalid email or PIN") from e

            # Verify master key with verification marker
            verification_ad = user.email_hash + b"verification"
            if not self.pin_manager.verify_master_key(
                master_key,
                credentials.verification_marker,
                verification_ad
            ):
                logger.error(f"Master key verification failed for user {user.user_id}")
                raise InvalidCredentialsError("Authentication verification failed")

            # Authentication successful!
            self.rate_limiter.record_successful_attempt(user.user_id)

            # Upgrade email hashing scheme if necessary
            if not user.email_salt or not user.email_lookup_hash:
                new_email_hash, new_email_salt = self.pin_manager.hash_email_for_storage(email)
                new_lookup_hash = self.pin_manager.hash_email_for_lookup(email)

                associated_data_new = new_email_hash + b"master_key"
                encrypted_master_key = self.pin_manager.encrypt_master_key(
                    master_key,
                    pin_derived_key,
                    associated_data_new,
                )

                verification_marker = self.pin_manager.create_verification_marker(
                    master_key,
                    new_email_hash + b"verification",
                )

                self.db.update_pin_credentials(
                    user.user_id,
                    credentials.pin_salt,
                    encrypted_master_key,
                    verification_marker,
                    kdf_algorithm=credentials.kdf_algorithm,
                    kdf_metadata=credentials.kdf_metadata,
                )
                self.db.update_email_identifiers(
                    user.user_id,
                    email_hash=new_email_hash,
                    email_lookup_hash=new_lookup_hash,
                    email_salt=new_email_salt,
                )

                user.email_hash = new_email_hash
                user.email_lookup_hash = new_lookup_hash
                user.email_salt = new_email_salt

            # Create session
            session = self._create_session(
                user.user_id,
                master_key,
                ip_address,
                user_agent,
            )

            # Update last login
            self.db.update_last_login(user.user_id)

            # Record successful attempt
            self.db.record_auth_attempt(
                user_id=user.user_id,
                email_hash=user.email_lookup_hash or user.email_hash,
                success=True,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason=None,
                normalized_email_hash=user_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=user_context.attempt_key,
            )
            self.rate_limiter.record_device_attempt(True, user_context)

            logger.info(f"Successful PIN authentication for user {user.user_id}")
            return session

        finally:
            # Wipe PIN from memory
            if 'pin_derived_key' in locals():
                secure_wipe(pin_derived_key)
            secure_wipe(bytearray(pin, 'utf-8'))

    def authenticate_with_password(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None,
        *,
        device_fingerprint: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> User:
        """
        Authenticate with email + password (for recovery/admin).

        Note: This does NOT decrypt the master key (requires PIN for that).
        This is used for password verification in PIN reset flows.

        Args:
            email: User's email address
            password: User's password
            ip_address: IP address of login attempt
            device_fingerprint: Stable device identifier, if available
            user_agent: Client user agent string, if available

        Returns:
            User object

        Raises:
            InvalidCredentialsError: Email or password is incorrect
            AccountLockedError: Account is locked
        """
        # Get user by email
        user = self.user_manager.get_user_by_email(email)
        lookup_hash = self.pin_manager.hash_email_for_lookup(email)
        attempt_context = self.rate_limiter.build_attempt_context(
            email=email,
            email_hash=lookup_hash,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
        )

        if not user:
            # Don't reveal that user doesn't exist
            self.db.record_auth_attempt(
                user_id=None,
                email_hash=lookup_hash,
                success=False,
                attempt_type='password',
                ip_address=ip_address,
                failure_reason='invalid_email',
                normalized_email_hash=attempt_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=attempt_context.attempt_key,
            )
            self.rate_limiter.record_device_attempt(False, attempt_context)
            raise InvalidCredentialsError("Invalid email or password")

        user_context = self.rate_limiter.build_attempt_context(
            email=email,
            email_hash=user.email_lookup_hash or user.email_hash,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            user_agent=user_agent,
        )

        # Check rate limiting
        try:
            self.rate_limiter.check_rate_limit(user.user_id)
        except (RateLimitError, AccountLockedError) as e:
            self.db.record_auth_attempt(
                user_id=user.user_id,
                email_hash=user.email_lookup_hash or user.email_hash,
                success=False,
                attempt_type='password',
                ip_address=ip_address,
                failure_reason='rate_limited' if isinstance(e, RateLimitError) else 'account_locked',
                normalized_email_hash=user_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=user_context.attempt_key,
            )
            self.rate_limiter.record_device_attempt(False, user_context)
            raise

        # Verify password
        with self.auth_queue.acquire("password_verify"):
            password_valid = self.user_manager.verify_password(user.user_id, password)

        if not password_valid:
            self.rate_limiter.record_failed_attempt(user.user_id)

            self.db.record_auth_attempt(
                user_id=user.user_id,
                email_hash=user.email_lookup_hash or user.email_hash,
                success=False,
                attempt_type='password',
                ip_address=ip_address,
                failure_reason='invalid_password',
                normalized_email_hash=user_context.normalized_email_hash,
                user_agent=user_agent,
                device_fingerprint=device_fingerprint,
                attempt_key=user_context.attempt_key,
            )

            logger.warning(f"Failed password authentication for user {user.user_id}")
            self.rate_limiter.record_device_attempt(False, user_context)
            raise InvalidCredentialsError("Invalid email or password")

        # Authentication successful
        self.rate_limiter.record_successful_attempt(user.user_id)

        self.db.record_auth_attempt(
            user_id=user.user_id,
            email_hash=user.email_lookup_hash or user.email_hash,
            success=True,
            attempt_type='password',
            ip_address=ip_address,
            failure_reason=None,
            normalized_email_hash=user_context.normalized_email_hash,
            user_agent=user_agent,
            device_fingerprint=device_fingerprint,
            attempt_key=user_context.attempt_key,
        )
        self.rate_limiter.record_device_attempt(True, user_context)

        logger.info(f"Successful password authentication for user {user.user_id}")
        return user

    def _create_session(
        self,
        user_id: int,
        master_key: Union[bytes, bytearray],
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> AuthSession:
        """
        Create new authentication session.

        Args:
            user_id: User ID
            master_key: Decrypted master vault key
            ip_address: IP address
            user_agent: User agent string describing the client

        Returns:
            AuthSession
        """
        # Normalize metadata to ensure consistent comparisons
        normalized_ip, normalized_user_agent = self._normalize_client_metadata(
            ip_address,
            user_agent,
        )

        # Generate unique session ID
        session_id = str(uuid.uuid4())

        # Calculate expiration
        created_at = datetime.now()
        expires_at = created_at + timedelta(minutes=self.config.session_timeout_minutes)

        # Create database session record
        self.db.create_session(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            ip_address=normalized_ip,
            user_agent=normalized_user_agent,
        )

        lock = self._session_locks[session_id]

        # Create in-memory session with master key
        session = AuthSession(
            session_id=session_id,
            user_id=user_id,
            master_key=master_key,
            created_at=created_at,
            expires_at=expires_at,
            lock=lock,
            ip_address=normalized_ip,
            user_agent=normalized_user_agent,
        )

        with lock:
            self._sessions[session_id] = session

        logger.info(f"Created session {session_id} for user {user_id}")
        return session

    def get_session(
        self,
        session_id: str,
        ip_address: str,
        user_agent: str
    ) -> Optional[AuthSession]:
        """
        Get active session by ID.

        Args:
            session_id: Session ID
            ip_address: IP address presented with the request
            user_agent: User agent presented with the request

        Returns:
            AuthSession or None if not found/expired

        Raises:
            SessionExpiredError: Session has expired
            SessionHijackingError: Client metadata does not match expectations
        """
        lock = self._session_locks[session_id]
        session: Optional[AuthSession] = None
        error: Optional[SessionExpiredError] = None
        should_remove_lock = False
        delete_from_db = False

        with lock:
            session = self._sessions.get(session_id)

            if not session:
                db_session = self.db.get_session(session_id)
                if not db_session:
                    should_remove_lock = True
                    session = None
                else:
                    should_remove_lock = True
                    error = SessionExpiredError("Session expired - please log in again")
            else:
                if session.is_expired():
                    session.close()
                    del self._sessions[session_id]
                    should_remove_lock = True
                    delete_from_db = True
                    error = SessionExpiredError("Session has expired")
                else:
                    idle_time = datetime.now() - session.last_activity
                    if idle_time.total_seconds() > (self.config.session_idle_timeout_minutes * 60):
                        logger.info(f"Session {session_id} expired due to inactivity")
                        session.close()
                        del self._sessions[session_id]
                        should_remove_lock = True
                        delete_from_db = True
                        error = SessionExpiredError("Session expired due to inactivity")
                    else:
                        self.db.update_session_activity(session_id)

        if session is not None and error is None:
            return session

        if delete_from_db:
            self.db.delete_session(session_id)

        if should_remove_lock:
            self._session_locks.pop(session_id, None)
        normalized_ip, normalized_user_agent = self._normalize_client_metadata(
            ip_address,
            user_agent,
        )

        session = self._sessions.get(session_id)
        db_session = self.db.get_session(session_id)

        if session is None and db_session is None:
            return None

        if session is None and db_session is not None:
            # Session exists in DB but not in memory (e.g., after restart)
            # User needs to re-authenticate
            raise SessionExpiredError("Session expired - please log in again")

        if session is not None and db_session is None:
            # Database state no longer has the session, treat as expired
            self.logout(session_id)
            raise SessionExpiredError("Session has expired")

        assert session is not None and db_session is not None

        stored_ip, stored_user_agent = self._normalize_client_metadata(
            db_session.ip_address,
            db_session.user_agent,
        )

        if stored_ip != normalized_ip or stored_user_agent != normalized_user_agent:
            audit_logger = get_audit_logger()
            audit_logger.log_event(
                AuditEventType.SUSPICIOUS_ACTIVITY,
                AuditSeverity.CRITICAL,
                "Session client metadata mismatch detected",
                {
                    "session_id": session_id,
                    "expected_ip": stored_ip,
                    "presented_ip": normalized_ip,
                    "expected_user_agent": stored_user_agent,
                    "presented_user_agent": normalized_user_agent,
                },
                user_id=str(db_session.user_id),
                source_ip=normalized_ip,
            )
            self.logout(session_id)
            raise SessionHijackingError("Session client metadata mismatch detected")

        # Check if expired
        if session.is_expired():
            self.logout(session_id)
            raise SessionExpiredError("Session has expired")

        if error:
            raise error

        return None

    @staticmethod
    def _normalize_client_metadata(
        ip_address: Optional[str],
        user_agent: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Normalize client metadata for consistent storage and comparison."""

        def normalize_ip(value: Optional[str]) -> Optional[str]:
            if value is None:
                return None
            normalized = value.strip()
            if not normalized:
                return None
            return normalized.lower()

        def normalize_user_agent(value: Optional[str]) -> Optional[str]:
            if value is None:
                return None
            normalized = " ".join(value.strip().split())
            if not normalized:
                return None
            return normalized

        return normalize_ip(ip_address), normalize_user_agent(user_agent)

    def logout(self, session_id: str) -> None:
        """
        End user session (logout).

        Wipes master key from memory and deletes session.

        Args:
            session_id: Session ID to terminate
        """
        lock = self._session_locks[session_id]

        with lock:
            session = self._sessions.pop(session_id, None)
            if session:
                session.close()

        self._session_locks.pop(session_id, None)

        # Delete from database
        self.db.delete_session(session_id)

        logger.info(f"Logged out session {session_id}")

    # ------------------------------------------------------------------
    # Access control helpers
    # ------------------------------------------------------------------

    def get_access_control(self) -> AccessControl:
        """Expose the shared AccessControl instance."""

        return self.access_control

    def grant_file_access(
        self,
        actor_user_id: int,
        target_user_id: int,
        file_id: str,
        permission: PermissionLevel,
    ) -> None:
        """Grant access to a file on behalf of the authenticated actor."""

        self.access_control.grant_access(actor_user_id, target_user_id, file_id, permission)

    def revoke_file_access(
        self,
        actor_user_id: int,
        target_user_id: int,
        file_id: str,
        permissions: Optional[List[PermissionLevel]] = None,
    ) -> None:
        """Revoke access from a file on behalf of the authenticated actor."""

        self.access_control.revoke_access(actor_user_id, target_user_id, file_id, permissions)

    def require_file_access(
        self,
        user_id: int,
        file_id: str,
        permission: PermissionLevel,
    ) -> None:
        """Ensure the user has the requested permission."""

        self.access_control.require_access(user_id, file_id, permission)

    def has_file_access(
        self,
        user_id: int,
        file_id: str,
        permission: PermissionLevel,
    ) -> bool:
        """Check if a user currently has a permission."""

        return self.access_control.has_access(user_id, file_id, permission)

    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions (should be called periodically).

        Returns:
            Number of sessions cleaned up
        """
        count = 0

        # Clean up in-memory sessions
        expired_sessions = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]

        for session_id in expired_sessions:
            self.logout(session_id)
            count += 1

        # Clean up database sessions
        db_count = self.db.delete_expired_sessions()
        count += db_count

        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions")

        return count

    def is_first_start(self) -> bool:
        """
        Check if this is the first time the application is started.

        Returns:
            True if no users exist (first-start), False otherwise
        """
        return not self.db.has_users()

    def get_user_count(self) -> int:
        """Get total number of registered users"""
        return self.db.get_user_count()
