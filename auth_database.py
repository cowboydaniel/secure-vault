"""
SecureVault Authentication Database Module

This module manages the SQLite database for user authentication,
including user accounts, credentials, sessions, and auth attempts.

Security Notes:
- PIN is NEVER stored in this database
- Master vault key is stored encrypted (requires PIN to decrypt)
- All passwords are hashed with Argon2id
- Database file has restrictive permissions (600)
"""

import sqlite3
import os
import logging
import json
import hashlib
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path

from auth_secrets import get_session_pepper
from instance_guard import InstanceGuard, TamperDetectedError

logger = logging.getLogger(__name__)


@dataclass
class User:
    """User account data"""
    user_id: int
    email_hash: bytes
    password_hash: bytes
    password_salt: bytes
    password_kdf: str
    password_kdf_metadata: Dict[str, Any]
    email_lookup_hash: Optional[bytes]
    email_salt: Optional[bytes]
    created_at: datetime
    last_login: Optional[datetime]
    is_locked: bool
    failed_attempts: int
    lockout_until: Optional[datetime]


@dataclass
class AuthCredentials:
    """User authentication credentials (PIN-derived)"""
    credential_id: int
    user_id: int
    pin_salt: bytes
    encrypted_master_key: bytes
    verification_marker: bytes
    created_at: datetime
    last_updated: datetime
    kdf_algorithm: str
    kdf_metadata: Dict[str, Any]


@dataclass
class Session:
    """User session data"""
    session_id: str
    user_id: int
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: Optional[str]
    user_agent: Optional[str]


@dataclass
class AuthAttempt:
    """Authentication attempt record"""
    attempt_id: int
    user_id: Optional[int]
    email_hash: Optional[bytes]
    timestamp: datetime
    success: bool
    attempt_type: str  # 'pin', 'password', 'recovery'
    ip_address: Optional[str]
    failure_reason: Optional[str]


class AuthDatabase:
    """
    Authentication database manager.

    Manages SQLite database for user authentication with tables:
    - users: User accounts
    - auth_credentials: PIN-derived encryption credentials
    - sessions: Active user sessions
    - auth_attempts: Authentication attempt history
    """

    INSTANCE_SECRET_KEY = "instance_secret"

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize authentication database.

        Args:
            db_path: Path to database file (default: ~/.secure_vault/users.db)
        """
        if db_path is None:
            config_dir = os.path.expanduser("~/.secure_vault")
            os.makedirs(config_dir, mode=0o700, exist_ok=True)
            db_path = os.path.join(config_dir, "users.db")

        self.db_path = db_path
        self.connection: Optional[sqlite3.Connection] = None

        self._instance_guard = InstanceGuard(self.db_path)

        # Create database and tables if they don't exist
        self._initialize_database()

        # Apply schema hardening migrations
        self._apply_migrations()

        # Set restrictive file permissions
        self._set_secure_permissions()
        self._instance_guard.verify_environment(self)

    @staticmethod
    def _parse_datetime(value: Optional[Any]) -> Optional[datetime]:
        """Coerce SQLite timestamp values into ``datetime`` objects."""

        if value is None:
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)

        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                try:
                    return datetime.fromtimestamp(float(value))
                except (TypeError, ValueError):
                    logger.warning("Unable to parse datetime value: %s", value)
                    return None

        logger.warning("Unexpected datetime value type: %s", type(value))
        return None

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        """Format datetimes for SQLite storage."""

        return value.strftime("%Y-%m-%d %H:%M:%S.%f")

    @staticmethod
    def _parse_datetime(value: Optional[Any]) -> Optional[datetime]:
        """Coerce SQLite timestamp values into ``datetime`` objects."""

        if value is None:
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)

        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                try:
                    return datetime.fromtimestamp(float(value))
                except (TypeError, ValueError):
                    logger.warning("Unable to parse datetime value: %s", value)
                    return None

        logger.warning("Unexpected datetime value type: %s", type(value))
        return None

    @staticmethod
    def _format_datetime(value: datetime) -> str:
        """Format datetimes for SQLite storage."""

        return value.strftime("%Y-%m-%d %H:%M:%S.%f")

    def _initialize_database(self):
        """Create database schema if it doesn't exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_hash BLOB NOT NULL UNIQUE,
                    email_lookup_hash BLOB UNIQUE,
                    email_salt BLOB,
                    password_hash BLOB NOT NULL,
                    password_salt BLOB NOT NULL,
                    password_kdf TEXT NOT NULL DEFAULT 'argon2id',
                    password_kdf_metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_locked BOOLEAN DEFAULT 0,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until TIMESTAMP,

                    CHECK (failed_attempts >= 0),
                    CHECK (is_locked IN (0, 1))
                )
            """)

            # Auth credentials table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_credentials (
                    credential_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    pin_salt BLOB NOT NULL,
                    encrypted_master_key BLOB NOT NULL,
                    verification_marker BLOB NOT NULL,
                    kdf_algorithm TEXT NOT NULL DEFAULT 'argon2id',
                    kdf_metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            """)

            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,

                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    CHECK (expires_at > created_at)
                )
            """)

            # Auth attempts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    email_hash BLOB,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN NOT NULL,
                    attempt_type TEXT NOT NULL,
                    ip_address TEXT,
                    failure_reason TEXT,

                    CHECK (success IN (0, 1)),
                    CHECK (attempt_type IN ('pin', 'password', 'recovery'))
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email_lookup ON users(email_lookup_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_credentials_user_id ON auth_credentials(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_user_id ON auth_attempts(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_timestamp ON auth_attempts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_email_hash ON auth_attempts(email_hash)")

            self._bind_instance_secret(cursor)

            conn.commit()
            logger.info("Authentication database initialized successfully")

    def _set_secure_permissions(self):
        """Set secure file permissions on database (owner read/write only)"""
        if os.path.exists(self.db_path):
            os.chmod(self.db_path, 0o600)  # rw------- (owner only)
            logger.debug(f"Set secure permissions (600) on {self.db_path}")

    def _hash_session_token(self, session_id: str) -> str:
        pepper = get_session_pepper()
        digest = hashlib.blake2b(session_id.encode('utf-8'), key=pepper, digest_size=32)
        return digest.hexdigest()

    @staticmethod
    def _serialize_metadata(metadata: Dict[str, Any]) -> str:
        return json.dumps(metadata or {}, sort_keys=True)

    @staticmethod
    def _deserialize_metadata(value: Optional[str]) -> Dict[str, Any]:
        if not value:
            return {}
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            logger.warning("Failed to decode metadata JSON: %s", value)
            return {}

    def _apply_migrations(self) -> None:
        """Ensure legacy databases receive the hardening columns."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("PRAGMA table_info(users)")
            user_columns = {row[1] for row in cursor.fetchall()}

            if "email_lookup_hash" not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN email_lookup_hash BLOB")
                cursor.execute("UPDATE users SET email_lookup_hash = email_hash WHERE email_lookup_hash IS NULL")

            if "email_salt" not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN email_salt BLOB")

            if "password_kdf" not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN password_kdf TEXT DEFAULT 'argon2id'")
                cursor.execute("UPDATE users SET password_kdf = 'argon2id' WHERE password_kdf IS NULL")

            if "password_kdf_metadata" not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN password_kdf_metadata TEXT DEFAULT '{}'")
                cursor.execute("UPDATE users SET password_kdf_metadata = '{}' WHERE password_kdf_metadata IS NULL")

            cursor.execute("PRAGMA table_info(auth_credentials)")
            cred_columns = {row[1] for row in cursor.fetchall()}

            if "kdf_algorithm" not in cred_columns:
                cursor.execute("ALTER TABLE auth_credentials ADD COLUMN kdf_algorithm TEXT DEFAULT 'argon2id'")
                cursor.execute("UPDATE auth_credentials SET kdf_algorithm = 'argon2id' WHERE kdf_algorithm IS NULL")

            if "kdf_metadata" not in cred_columns:
                cursor.execute("ALTER TABLE auth_credentials ADD COLUMN kdf_metadata TEXT DEFAULT '{}'")
                cursor.execute("UPDATE auth_credentials SET kdf_metadata = '{}' WHERE kdf_metadata IS NULL")

            cursor.execute("PRAGMA table_info(sessions)")
            session_columns = {row[1] for row in cursor.fetchall()}

            if "session_id" in session_columns:
                cursor.execute("SELECT session_id FROM sessions")
                rows = cursor.fetchall()
                for (session_id,) in rows:
                    if not session_id:
                        continue
                    # Detect UUID-like tokens to avoid double hashing
                    if '-' in session_id or len(session_id) in {32, 36}:
                        hashed = self._hash_session_token(session_id)
                        cursor.execute(
                            "UPDATE sessions SET session_id = ? WHERE session_id = ?",
                            (hashed, session_id),
                        )

            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='system_state'")
            if cursor.fetchone() is None:
                cursor.execute("""
                    CREATE TABLE system_state (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            conn.commit()

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with proper settings"""
        conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row  # Allow dict-like access
        conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
        return conn

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None

    # ==================== User Management ====================

    def create_user(
        self,
        email_hash: bytes,
        email_lookup_hash: bytes,
        email_salt: bytes,
        password_hash: bytes,
        password_salt: bytes,
        password_kdf: str,
        password_kdf_metadata: Dict[str, Any],
        pin_salt: bytes,
        encrypted_master_key: bytes,
        verification_marker: bytes,
        pin_kdf_algorithm: str,
        pin_kdf_metadata: Dict[str, Any],
    ) -> int:
        """
        Create a new user account with credentials.

        Args:
            email_hash: BLAKE2b hash of email
            password_hash: Argon2id hash of password
            password_salt: Salt used for password hashing
            pin_salt: Salt used for PIN derivation
            encrypted_master_key: Master vault key encrypted with PIN-derived key
            verification_marker: Verification string encrypted with master key

        Returns:
            user_id: New user's ID

        Raises:
            sqlite3.IntegrityError: Email already exists
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert user
            cursor.execute(
                """
                INSERT INTO users (
                    email_hash,
                    email_lookup_hash,
                    email_salt,
                    password_hash,
                    password_salt,
                    password_kdf,
                    password_kdf_metadata
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email_hash,
                    email_lookup_hash,
                    email_salt,
                    password_hash,
                    password_salt,
                    password_kdf,
                    self._serialize_metadata(password_kdf_metadata),
                ),
            )

            user_id = cursor.lastrowid

            # Insert auth credentials
            cursor.execute(
                """
                INSERT INTO auth_credentials
                (user_id, pin_salt, encrypted_master_key, verification_marker, kdf_algorithm, kdf_metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    pin_salt,
                    encrypted_master_key,
                    verification_marker,
                    pin_kdf_algorithm,
                    self._serialize_metadata(pin_kdf_metadata),
                ),
            )

            conn.commit()
            logger.info(f"Created new user with ID {user_id}")
            return user_id

    def _row_to_user(self, row: sqlite3.Row) -> User:
        return User(
            user_id=row['user_id'],
            email_hash=row['email_hash'],
            password_hash=row['password_hash'],
            password_salt=row['password_salt'],
            password_kdf=row['password_kdf'] or 'argon2id',
            password_kdf_metadata=self._deserialize_metadata(row['password_kdf_metadata']),
            email_lookup_hash=row['email_lookup_hash'],
            email_salt=row['email_salt'],
            created_at=self._parse_datetime(row['created_at']),
            last_login=self._parse_datetime(row['last_login']),
            is_locked=bool(row['is_locked']),
            failed_attempts=row['failed_attempts'],
            lockout_until=self._parse_datetime(row['lockout_until'])
        )

    def get_user_by_email_hash(self, email_hash: bytes) -> Optional[User]:
        """Get user by legacy email hash"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email_hash = ?", (email_hash,))
            row = cursor.fetchone()

            if row:
                return self._row_to_user(row)
            return None

    def get_user_by_email_lookup_hash(self, email_lookup_hash: bytes) -> Optional[User]:
        """Get user by peppered lookup hash"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email_lookup_hash = ?", (email_lookup_hash,))
            row = cursor.fetchone()

            if row:
                return self._row_to_user(row)
                return User(
                    user_id=row['user_id'],
                    email_hash=row['email_hash'],
                    password_hash=row['password_hash'],
                    password_salt=row['password_salt'],
                    created_at=self._parse_datetime(row['created_at']),
                    last_login=self._parse_datetime(row['last_login']),
                    is_locked=bool(row['is_locked']),
                    failed_attempts=row['failed_attempts'],
                    lockout_until=self._parse_datetime(row['lockout_until'])
                )
            return None

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()

            if row:
                return self._row_to_user(row)
                return User(
                    user_id=row['user_id'],
                    email_hash=row['email_hash'],
                    password_hash=row['password_hash'],
                    password_salt=row['password_salt'],
                    created_at=self._parse_datetime(row['created_at']),
                    last_login=self._parse_datetime(row['last_login']),
                    is_locked=bool(row['is_locked']),
                    failed_attempts=row['failed_attempts'],
                    lockout_until=self._parse_datetime(row['lockout_until'])
                )
            return None

    def update_last_login(self, user_id: int):
        """Update user's last login timestamp"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET last_login = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (user_id,))
            conn.commit()

    def update_password(
        self,
        user_id: int,
        password_hash: bytes,
        password_salt: bytes,
        *,
        password_kdf: Optional[str] = None,
        password_kdf_metadata: Optional[Dict[str, Any]] = None,
    ):
        """Update user's password"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET password_hash = ?,
                    password_salt = ?,
                    password_kdf = COALESCE(?, password_kdf),
                    password_kdf_metadata = COALESCE(?, password_kdf_metadata)
                WHERE user_id = ?
            """, (
                password_hash,
                password_salt,
                password_kdf,
                self._serialize_metadata(password_kdf_metadata) if password_kdf_metadata is not None else None,
                user_id,
            ))
            conn.commit()
            logger.info(f"Updated password for user {user_id}")

    def increment_failed_attempts(self, user_id: int) -> int:
        """
        Increment failed login attempts counter.

        Returns:
            New failed_attempts count
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET failed_attempts = failed_attempts + 1
                WHERE user_id = ?
            """, (user_id,))

            cursor.execute("SELECT failed_attempts FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            conn.commit()

            return result['failed_attempts'] if result else 0

    def reset_failed_attempts(self, user_id: int):
        """Reset failed login attempts counter"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET failed_attempts = 0, is_locked = 0, lockout_until = NULL
                WHERE user_id = ?
            """, (user_id,))
            conn.commit()

    def update_email_identifiers(
        self,
        user_id: int,
        *,
        email_hash: bytes,
        email_lookup_hash: bytes,
        email_salt: bytes,
    ) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users
                SET email_hash = ?,
                    email_lookup_hash = ?,
                    email_salt = ?
                WHERE user_id = ?
                """,
                (email_hash, email_lookup_hash, email_salt, user_id),
            )
            conn.commit()

    def lock_account(self, user_id: int, lockout_duration_minutes: int = 30):
        """Lock account for specified duration"""
        lockout_until = datetime.now() + timedelta(minutes=lockout_duration_minutes)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET is_locked = 1, lockout_until = ?
                WHERE user_id = ?
            """, (self._format_datetime(lockout_until), user_id))
            conn.commit()
            logger.warning(f"Locked account {user_id} until {lockout_until}")

    def unlock_account(self, user_id: int):
        """Manually unlock account"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET is_locked = 0, lockout_until = NULL, failed_attempts = 0
                WHERE user_id = ?
            """, (user_id,))
            conn.commit()
            logger.info(f"Unlocked account {user_id}")

    def is_account_locked(self, user_id: int) -> bool:
        """Check if account is currently locked"""
        user = self.get_user_by_id(user_id)
        if not user:
            return False

        # Check if locked and lockout hasn't expired
        if user.is_locked:
            if user.lockout_until and datetime.now() >= user.lockout_until:
                # Lockout expired, auto-unlock
                self.unlock_account(user_id)
                return False
            return True

        return False

    # ==================== Auth Credentials ====================

    def get_credentials(self, user_id: int) -> Optional[AuthCredentials]:
        """Get user's authentication credentials"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM auth_credentials WHERE user_id = ?
            """, (user_id,))
            row = cursor.fetchone()

            if row:
                return AuthCredentials(
                    credential_id=row['credential_id'],
                    user_id=row['user_id'],
                    pin_salt=row['pin_salt'],
                    encrypted_master_key=row['encrypted_master_key'],
                    verification_marker=row['verification_marker'],
                    created_at=self._parse_datetime(row['created_at']),
                    last_updated=self._parse_datetime(row['last_updated']),
                    kdf_algorithm=row['kdf_algorithm'] or 'argon2id',
                    kdf_metadata=self._deserialize_metadata(row['kdf_metadata']),
                )
            return None

    def update_pin_credentials(
        self,
        user_id: int,
        pin_salt: bytes,
        encrypted_master_key: bytes,
        verification_marker: bytes,
        *,
        kdf_algorithm: Optional[str] = None,
        kdf_metadata: Optional[Dict[str, Any]] = None,
    ):
        """Update PIN-derived credentials (for PIN reset)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE auth_credentials
                SET pin_salt = ?,
                    encrypted_master_key = ?,
                    verification_marker = ?,
                    last_updated = CURRENT_TIMESTAMP,
                    kdf_algorithm = COALESCE(?, kdf_algorithm),
                    kdf_metadata = COALESCE(?, kdf_metadata)
                WHERE user_id = ?
            """, (
                pin_salt,
                encrypted_master_key,
                verification_marker,
                kdf_algorithm,
                self._serialize_metadata(kdf_metadata) if kdf_metadata is not None else None,
                user_id,
            ))
            conn.commit()
            logger.info(f"Updated PIN credentials for user {user_id}")

    # ==================== Session Management ====================

    def create_session(
        self,
        session_id: str,
        user_id: int,
        expires_at: datetime,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Session:
        """Create a new session"""
        session_hash = self._hash_session_token(session_id)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO sessions
                (session_id, user_id, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_hash, user_id, self._format_datetime(expires_at), ip_address, user_agent),
            )
            conn.commit()

            logger.info(f"Created session {session_id} for user {user_id}")

            return Session(
                session_id=session_hash,
                user_id=user_id,
                created_at=datetime.now(),
                expires_at=expires_at,
                last_activity=datetime.now(),
                ip_address=ip_address,
                user_agent=user_agent
            )

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        session_hash = self._hash_session_token(session_id)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_hash,))
            row = cursor.fetchone()

            if row:
                return Session(
                    session_id=row['session_id'],
                    user_id=row['user_id'],
                    created_at=self._parse_datetime(row['created_at']),
                    expires_at=self._parse_datetime(row['expires_at']),
                    last_activity=self._parse_datetime(row['last_activity']),
                    ip_address=row['ip_address'],
                    user_agent=row['user_agent']
                )
            return None

    def update_session_activity(self, session_id: str):
        """Update session's last activity timestamp"""
        session_hash = self._hash_session_token(session_id)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions
                SET last_activity = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_hash,))
            conn.commit()

    def delete_session(self, session_id: str):
        """Delete session (logout)"""
        session_hash = self._hash_session_token(session_id)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_hash,))
            conn.commit()
            logger.info(f"Deleted session {session_id}")

    def delete_expired_sessions(self):
        """Clean up expired sessions"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP
            """)
            deleted = cursor.rowcount
            conn.commit()

            if deleted > 0:
                logger.info(f"Deleted {deleted} expired sessions")

            return deleted

    # ==================== Auth Attempts ====================

    def record_auth_attempt(
        self,
        user_id: Optional[int],
        email_hash: Optional[bytes],
        success: bool,
        attempt_type: str,
        ip_address: Optional[str] = None,
        failure_reason: Optional[str] = None
    ) -> int:
        """
        Record authentication attempt.

        Args:
            user_id: User ID (None if user not found)
            email_hash: Email hash (for tracking attempts on non-existent accounts)
            success: Whether attempt was successful
            attempt_type: 'pin', 'password', or 'recovery'
            ip_address: IP address of attempt
            failure_reason: Reason for failure (e.g., 'invalid_pin', 'account_locked')

        Returns:
            attempt_id: ID of recorded attempt
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO auth_attempts
                (user_id, email_hash, success, attempt_type, ip_address, failure_reason)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (user_id, email_hash, success, attempt_type, ip_address, failure_reason))

            attempt_id = cursor.lastrowid
            conn.commit()

            return attempt_id

    def get_recent_attempts(
        self,
        user_id: Optional[int] = None,
        email_hash: Optional[bytes] = None,
        limit: int = 10
    ) -> List[AuthAttempt]:
        """Get recent authentication attempts"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if user_id is not None:
                cursor.execute("""
                    SELECT * FROM auth_attempts
                    WHERE user_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (user_id, limit))
            elif email_hash is not None:
                cursor.execute("""
                    SELECT * FROM auth_attempts
                    WHERE email_hash = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (email_hash, limit))
            else:
                cursor.execute("""
                    SELECT * FROM auth_attempts
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (limit,))

            rows = cursor.fetchall()
            attempts = []

            for row in rows:
                attempts.append(AuthAttempt(
                    attempt_id=row['attempt_id'],
                    user_id=row['user_id'],
                    email_hash=row['email_hash'],
                    timestamp=self._parse_datetime(row['timestamp']),
                    success=bool(row['success']),
                    attempt_type=row['attempt_type'],
                    ip_address=row['ip_address'],
                    failure_reason=row['failure_reason']
                ))

            return attempts

    # ==================== Utility Methods ====================

    def database_exists(self) -> bool:
        """Check if database file exists (for first-start detection)"""
        return os.path.exists(self.db_path)

    def has_users(self) -> bool:
        """Check if any users exist in database"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users")
            result = cursor.fetchone()
            return result['count'] > 0

    def get_user_count(self) -> int:
        """Get total number of users"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM users")
            result = cursor.fetchone()
            return result['count']

    def get_instance_secret(self) -> Optional[str]:
        """Return the stored instance binding hash, if available."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM system_state WHERE key = ?",
                (self.INSTANCE_SECRET_KEY,)
            )
            row = cursor.fetchone()
            return row['value'] if row else None

    def set_instance_secret(self, secret_hash: str) -> None:
        """Persist or update the stored instance binding hash."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO system_state (key, value, created_at, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (self.INSTANCE_SECRET_KEY, secret_hash)
            )
            conn.commit()

    @staticmethod
    def hash_instance_secret(secret: bytes) -> str:
        """Derive a fixed digest for the instance binding secret."""
        digest = hashlib.blake2b(secret, digest_size=32)
        return digest.hexdigest()

    def get_failed_attempts_since(
        self,
        since: datetime,
        email_hash: Optional[bytes] = None,
    ) -> List[AuthAttempt]:
        """Fetch failed authentication attempts within the provided window."""

        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = [
                "SELECT * FROM auth_attempts WHERE success = 0 AND timestamp >= ?"
            ]
            params: List[Any] = [self._format_datetime(since)]

            if email_hash is not None:
                query.append("AND email_hash = ?")
                params.append(email_hash)

            query.append("ORDER BY timestamp ASC")
            cursor.execute(" ".join(query), params)

            rows = cursor.fetchall()
            attempts: List[AuthAttempt] = []

            for row in rows:
                attempts.append(
                    AuthAttempt(
                        attempt_id=row['attempt_id'],
                        user_id=row['user_id'],
                        email_hash=row['email_hash'],
                        timestamp=self._parse_datetime(row['timestamp']),
                        success=bool(row['success']),
                        attempt_type=row['attempt_type'],
                        ip_address=row['ip_address'],
                        failure_reason=row['failure_reason'],
                    )
                )

            return attempts

    def _bind_instance_secret(self, cursor: sqlite3.Cursor) -> None:
        """Ensure the authentication database is bound to the guard secret."""

        guard = getattr(self, "_instance_guard", None)
        if guard is None:
            return

        guard_secret = guard.get_secret()
        expected_hash = self.hash_instance_secret(guard_secret)

        cursor.execute(
            "SELECT value FROM system_state WHERE key = ?",
            (self.INSTANCE_SECRET_KEY,)
        )
        row = cursor.fetchone()

        status = guard.status

        if row is None:
            if not guard.allows_initial_binding():
                reason = "missing_instance_secret" if status == "provisioned" else "initial_binding_blocked"
                guard.lockdown(reason)
                raise TamperDetectedError(
                    "Authentication store integrity verification failed; manual recovery required."
                )

            cursor.execute(
                """
                INSERT INTO system_state (key, value, created_at, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """,
                (self.INSTANCE_SECRET_KEY, expected_hash)
            )
        elif row['value'] != expected_hash:
            guard.lockdown("binding_mismatch")
            raise TamperDetectedError(
                "Authentication store integrity verification failed; manual recovery required."
            )

        guard.mark_provisioned()
