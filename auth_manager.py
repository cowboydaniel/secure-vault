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

import os
import uuid
import logging
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass

from auth_database import AuthDatabase, Session, User
from user_manager import UserManager
from pin_manager import PINManager
from rate_limiter import RateLimiter, RateLimitError, AccountLockedError
from secure_memory import secure_wipe
from instance_guard import TamperDetectedError

logger = logging.getLogger(__name__)


@dataclass
class AuthConfig:
    """Authentication configuration"""
    session_timeout_minutes: int = 30      # Session expires after 30 minutes
    session_idle_timeout_minutes: int = 15  # Auto-logout after 15 minutes idle
    max_concurrent_sessions: int = 1        # Only one session per user


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
        master_key: bytes,
        created_at: datetime,
        expires_at: datetime
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
        self._master_key = master_key  # SENSITIVE: Stored in memory
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_activity = datetime.now()

    def get_master_key(self) -> bytes:
        """
        Get master vault key for encryption/decryption operations.

        Returns:
            Master key (32 bytes)

        Raises:
            SessionExpiredError: If session has expired
        """
        if self.is_expired():
            raise SessionExpiredError("Session has expired")

        self.last_activity = datetime.now()
        return self._master_key

    def is_expired(self) -> bool:
        """Check if session has expired"""
        return datetime.now() >= self.expires_at

    def close(self):
        """Close session and wipe master key from memory"""
        if self._master_key:
            secure_wipe(self._master_key)
            self._master_key = None

    def __del__(self):
        """Ensure master key is wiped when session is garbage collected"""
        self.close()


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
        config: Optional[AuthConfig] = None
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

        # Active sessions (in-memory)
        self._sessions: Dict[str, AuthSession] = {}

        logger.info("Authentication manager initialized")

    def authenticate_with_pin(
        self,
        email: str,
        pin: str,
        ip_address: Optional[str] = None
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

        Returns:
            AuthSession with decrypted master key

        Raises:
            InvalidCredentialsError: Email or PIN is incorrect
            AccountLockedError: Account is locked due to failed attempts
            RateLimitError: Too many attempts, must wait
        """
        email_lookup_hash = self.pin_manager.hash_email_for_lookup(email)

        try:
            self.rate_limiter.check_global_rate_limit(email_lookup_hash)
        except RateLimitError as exc:
            self.db.record_auth_attempt(
                user_id=None,
                email_hash=email_lookup_hash,
                success=False,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason='device_rate_limited'
            )
            raise

        # Get user by email
        user = self.user_manager.get_user_by_email(email)
        if not user:
            # Don't reveal that user doesn't exist
            # Record attempt with email hash for tracking
            email_hash = self.pin_manager.hash_email_for_lookup(email)
            self.db.record_auth_attempt(
                user_id=None,
                email_hash=email_lookup_hash,
                success=False,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason='invalid_email'
            )
            raise InvalidCredentialsError("Invalid email or PIN")

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
                failure_reason='rate_limited' if isinstance(e, RateLimitError) else 'account_locked'
            )
            raise

        # Get auth credentials
        credentials = self.db.get_credentials(user.user_id)
        if not credentials:
            logger.error(f"No credentials found for user {user.user_id}")
            raise InvalidCredentialsError("Invalid email or PIN")

        try:
            # Derive key from PIN
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
                    failure_reason='invalid_pin'
                )

                logger.warning(f"Failed PIN authentication for user {user.user_id}")
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
            session = self._create_session(user.user_id, master_key, ip_address)

            # Update last login
            self.db.update_last_login(user.user_id)

            # Record successful attempt
            self.db.record_auth_attempt(
                user_id=user.user_id,
                email_hash=user.email_lookup_hash or user.email_hash,
                success=True,
                attempt_type='pin',
                ip_address=ip_address,
                failure_reason=None
            )

            logger.info(f"Successful PIN authentication for user {user.user_id}")
            return session

        finally:
            # Wipe PIN from memory
            if 'pin_derived_key' in locals():
                secure_wipe(pin_derived_key)
            secure_wipe(pin.encode('utf-8'))

    def authenticate_with_password(
        self,
        email: str,
        password: str,
        ip_address: Optional[str] = None
    ) -> User:
        """
        Authenticate with email + password (for recovery/admin).

        Note: This does NOT decrypt the master key (requires PIN for that).
        This is used for password verification in PIN reset flows.

        Args:
            email: User's email address
            password: User's password
            ip_address: IP address of login attempt

        Returns:
            User object

        Raises:
            InvalidCredentialsError: Email or password is incorrect
            AccountLockedError: Account is locked
        """
        # Get user by email
        user = self.user_manager.get_user_by_email(email)
        if not user:
            # Don't reveal that user doesn't exist
            email_hash = self.pin_manager.hash_email_for_lookup(email)
            self.db.record_auth_attempt(
                user_id=None,
                email_hash=email_hash,
                success=False,
                attempt_type='password',
                ip_address=ip_address,
                failure_reason='invalid_email'
            )
            raise InvalidCredentialsError("Invalid email or password")

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
                failure_reason='rate_limited' if isinstance(e, RateLimitError) else 'account_locked'
            )
            raise

        # Verify password
        if not self.user_manager.verify_password(user.user_id, password):
            self.rate_limiter.record_failed_attempt(user.user_id)

            self.db.record_auth_attempt(
                user_id=user.user_id,
                email_hash=user.email_lookup_hash or user.email_hash,
                success=False,
                attempt_type='password',
                ip_address=ip_address,
                failure_reason='invalid_password'
            )

            logger.warning(f"Failed password authentication for user {user.user_id}")
            raise InvalidCredentialsError("Invalid email or password")

        # Authentication successful
        self.rate_limiter.record_successful_attempt(user.user_id)

        self.db.record_auth_attempt(
            user_id=user.user_id,
            email_hash=user.email_lookup_hash or user.email_hash,
            success=True,
            attempt_type='password',
            ip_address=ip_address,
            failure_reason=None
        )

        logger.info(f"Successful password authentication for user {user.user_id}")
        return user

    def _create_session(
        self,
        user_id: int,
        master_key: bytes,
        ip_address: Optional[str] = None
    ) -> AuthSession:
        """
        Create new authentication session.

        Args:
            user_id: User ID
            master_key: Decrypted master vault key
            ip_address: IP address

        Returns:
            AuthSession
        """
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
            ip_address=ip_address
        )

        # Create in-memory session with master key
        session = AuthSession(
            session_id=session_id,
            user_id=user_id,
            master_key=master_key,
            created_at=created_at,
            expires_at=expires_at
        )

        self._sessions[session_id] = session

        logger.info(f"Created session {session_id} for user {user_id}")
        return session

    def get_session(self, session_id: str) -> Optional[AuthSession]:
        """
        Get active session by ID.

        Args:
            session_id: Session ID

        Returns:
            AuthSession or None if not found/expired

        Raises:
            SessionExpiredError: Session has expired
        """
        session = self._sessions.get(session_id)

        if not session:
            # Check if session exists in database
            db_session = self.db.get_session(session_id)
            if not db_session:
                return None

            # Session exists in DB but not in memory (e.g., after restart)
            # User needs to re-authenticate
            raise SessionExpiredError("Session expired - please log in again")

        # Check if expired
        if session.is_expired():
            self.logout(session_id)
            raise SessionExpiredError("Session has expired")

        # Check idle timeout
        idle_time = datetime.now() - session.last_activity
        if idle_time.total_seconds() > (self.config.session_idle_timeout_minutes * 60):
            logger.info(f"Session {session_id} expired due to inactivity")
            self.logout(session_id)
            raise SessionExpiredError("Session expired due to inactivity")

        # Update activity timestamp in database
        self.db.update_session_activity(session_id)

        return session

    def logout(self, session_id: str) -> None:
        """
        End user session (logout).

        Wipes master key from memory and deletes session.

        Args:
            session_id: Session ID to terminate
        """
        # Get session
        session = self._sessions.get(session_id)

        if session:
            # Wipe master key from memory
            session.close()

            # Remove from memory
            del self._sessions[session_id]

        # Delete from database
        self.db.delete_session(session_id)

        logger.info(f"Logged out session {session_id}")

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
