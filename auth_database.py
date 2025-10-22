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
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class User:
    """User account data"""
    user_id: int
    email_hash: bytes
    password_hash: bytes
    password_salt: bytes
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

        # Create database and tables if they don't exist
        self._initialize_database()

        # Set restrictive file permissions
        self._set_secure_permissions()

    def _initialize_database(self):
        """Create database schema if it doesn't exist"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email_hash BLOB NOT NULL UNIQUE,
                    password_hash BLOB NOT NULL,
                    password_salt BLOB NOT NULL,
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

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users(email_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_credentials_user_id ON auth_credentials(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_user_id ON auth_attempts(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_timestamp ON auth_attempts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_auth_attempts_email_hash ON auth_attempts(email_hash)")

            conn.commit()
            logger.info("Authentication database initialized successfully")

    def _set_secure_permissions(self):
        """Set secure file permissions on database (owner read/write only)"""
        if os.path.exists(self.db_path):
            os.chmod(self.db_path, 0o600)  # rw------- (owner only)
            logger.debug(f"Set secure permissions (600) on {self.db_path}")

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
        password_hash: bytes,
        password_salt: bytes,
        pin_salt: bytes,
        encrypted_master_key: bytes,
        verification_marker: bytes
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
            cursor.execute("""
                INSERT INTO users (email_hash, password_hash, password_salt)
                VALUES (?, ?, ?)
            """, (email_hash, password_hash, password_salt))

            user_id = cursor.lastrowid

            # Insert auth credentials
            cursor.execute("""
                INSERT INTO auth_credentials
                (user_id, pin_salt, encrypted_master_key, verification_marker)
                VALUES (?, ?, ?, ?)
            """, (user_id, pin_salt, encrypted_master_key, verification_marker))

            conn.commit()
            logger.info(f"Created new user with ID {user_id}")
            return user_id

    def get_user_by_email_hash(self, email_hash: bytes) -> Optional[User]:
        """Get user by email hash"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email_hash = ?", (email_hash,))
            row = cursor.fetchone()

            if row:
                return User(
                    user_id=row['user_id'],
                    email_hash=row['email_hash'],
                    password_hash=row['password_hash'],
                    password_salt=row['password_salt'],
                    created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                    last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                    is_locked=bool(row['is_locked']),
                    failed_attempts=row['failed_attempts'],
                    lockout_until=datetime.fromisoformat(row['lockout_until']) if row['lockout_until'] else None
                )
            return None

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()

            if row:
                return User(
                    user_id=row['user_id'],
                    email_hash=row['email_hash'],
                    password_hash=row['password_hash'],
                    password_salt=row['password_salt'],
                    created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                    last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
                    is_locked=bool(row['is_locked']),
                    failed_attempts=row['failed_attempts'],
                    lockout_until=datetime.fromisoformat(row['lockout_until']) if row['lockout_until'] else None
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

    def update_password(self, user_id: int, password_hash: bytes, password_salt: bytes):
        """Update user's password"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET password_hash = ?, password_salt = ?
                WHERE user_id = ?
            """, (password_hash, password_salt, user_id))
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

    def lock_account(self, user_id: int, lockout_duration_minutes: int = 30):
        """Lock account for specified duration"""
        lockout_until = datetime.now() + timedelta(minutes=lockout_duration_minutes)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users
                SET is_locked = 1, lockout_until = ?
                WHERE user_id = ?
            """, (lockout_until.isoformat(), user_id))
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
                    created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                    last_updated=datetime.fromisoformat(row['last_updated']) if row['last_updated'] else None
                )
            return None

    def update_pin_credentials(
        self,
        user_id: int,
        pin_salt: bytes,
        encrypted_master_key: bytes,
        verification_marker: bytes
    ):
        """Update PIN-derived credentials (for PIN reset)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE auth_credentials
                SET pin_salt = ?,
                    encrypted_master_key = ?,
                    verification_marker = ?,
                    last_updated = CURRENT_TIMESTAMP
                WHERE user_id = ?
            """, (pin_salt, encrypted_master_key, verification_marker, user_id))
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
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO sessions
                (session_id, user_id, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, user_id, expires_at.isoformat(), ip_address, user_agent))
            conn.commit()

            logger.info(f"Created session {session_id} for user {user_id}")

            return Session(
                session_id=session_id,
                user_id=user_id,
                created_at=datetime.now(),
                expires_at=expires_at,
                last_activity=datetime.now(),
                ip_address=ip_address,
                user_agent=user_agent
            )

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()

            if row:
                return Session(
                    session_id=row['session_id'],
                    user_id=row['user_id'],
                    created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
                    expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None,
                    last_activity=datetime.fromisoformat(row['last_activity']) if row['last_activity'] else None,
                    ip_address=row['ip_address'],
                    user_agent=row['user_agent']
                )
            return None

    def update_session_activity(self, session_id: str):
        """Update session's last activity timestamp"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE sessions
                SET last_activity = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_id,))
            conn.commit()

    def delete_session(self, session_id: str):
        """Delete session (logout)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
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
                    timestamp=datetime.fromisoformat(row['timestamp']) if row['timestamp'] else None,
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
