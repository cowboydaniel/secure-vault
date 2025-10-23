"""
Secure Metadata Management

Manages metadata for encrypted files including file information,
encryption parameters, and integrity data in a secure SQLite database.
"""

import atexit
import sqlite3
import json
import time
import logging
import os
from enum import Enum
from typing import Dict, Any, Optional, List, Tuple, Union
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass

from error_handling import emit_user_message


logger = logging.getLogger(__name__)

class PermissionLevel(Enum):
    """Supported permission levels for file access control."""

    READ = "read"
    WRITE = "write"
    MANAGE = "manage"

    @classmethod
    def from_value(cls, value: Union["PermissionLevel", str]) -> "PermissionLevel":
        """Normalize an incoming permission value."""

        if isinstance(value, PermissionLevel):
            return value
        try:
            return cls(value)
        except ValueError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown permission level: {value}") from exc

from auth_database import ConnectionPool


@dataclass
class FileMetadata:
    """Metadata for an encrypted file"""
    file_id: str
    original_name: str
    original_size: int
    encrypted_size: int
    encryption_timestamp: float
    encryption_algorithm: str
    key_id: str
    iv: bytes
    integrity_hash: str
    compression_used: bool
    compression_algorithm: Optional[str] = None
    shares_total: Optional[int] = None
    shares_threshold: Optional[int] = None
    tags: Optional[List[str]] = None
    custom_metadata: Optional[Dict[str, Any]] = None


@dataclass
class FilePermission:
    """Represents a granted permission for a user on a file."""

    file_id: str
    user_id: int
    permission: PermissionLevel
    granted_by: Optional[int]
    granted_at: float
    revoked_at: Optional[float] = None


class MetadataManager:
    _registered_cleanup_paths = set()
    """
    Secure metadata management using encrypted SQLite database

    Features:
    - Secure storage of file metadata
    - Encryption parameter tracking
    - Integrity verification data
    - Query and search capabilities
    - Backup and export functionality
    """

    def __init__(self, db_path: str = "metadata.db", encryption_key: Optional[bytes] = None):
        """
        Initialize metadata manager

        Args:
            db_path: Path to SQLite database
            encryption_key: Key for database encryption (future enhancement)
        """
        self.db_path = Path(db_path)
        self.encryption_key = encryption_key

        self._pool = ConnectionPool(
            str(self.db_path),
            max_size=5,
            connect_kwargs={"check_same_thread": False},
        )
        atexit.register(self.close)

        self._last_error_message: Optional[str] = None
        self._init_database()
        self._register_shutdown_cleanup()

    @property
    def last_error_message(self) -> Optional[str]:
        """Return the most recent sanitized error message."""

        return self._last_error_message

    def _init_database(self):
        """Initialize database schema"""
        with self._pool.connection() as conn:
            cursor = conn.cursor()

            # Main metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_metadata (
                    file_id TEXT PRIMARY KEY,
                    original_name TEXT NOT NULL,
                    original_size INTEGER NOT NULL,
                    encrypted_size INTEGER NOT NULL,
                    encryption_timestamp REAL NOT NULL,
                    encryption_algorithm TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    iv BLOB NOT NULL,
                    integrity_hash TEXT NOT NULL,
                    compression_used BOOLEAN NOT NULL,
                    compression_algorithm TEXT,
                    shares_total INTEGER,
                    shares_threshold INTEGER,
                    tags TEXT,
                    custom_metadata TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            ''')
        conn = self._get_connection()
        cursor = conn.cursor()

        # Ensure foreign keys are enforced for integrity
        cursor.execute("PRAGMA foreign_keys = ON")

        # Main metadata table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_metadata (
                file_id TEXT PRIMARY KEY,
                original_name TEXT NOT NULL,
                original_size INTEGER NOT NULL,
                encrypted_size INTEGER NOT NULL,
                encryption_timestamp REAL NOT NULL,
                encryption_algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                iv BLOB NOT NULL,
                integrity_hash TEXT NOT NULL,
                compression_used BOOLEAN NOT NULL,
                compression_algorithm TEXT,
                shares_total INTEGER,
                shares_threshold INTEGER,
                tags TEXT,
                custom_metadata TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        ''')

        # Access control table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_permissions (
                file_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                permission TEXT NOT NULL,
                granted_by INTEGER,
                granted_at REAL NOT NULL,
                revoked_at REAL,
                PRIMARY KEY (file_id, user_id, permission),
                FOREIGN KEY (file_id) REFERENCES file_metadata(file_id)
                    ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_permissions_user
            ON file_permissions(user_id)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_permissions_file
            ON file_permissions(file_id)
        ''')

        # Index for faster queries
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_original_name
            ON file_metadata(original_name)
        ''')

            # Index for faster queries
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_original_name
                ON file_metadata(original_name)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_encryption_timestamp
                ON file_metadata(encryption_timestamp)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_key_id
                ON file_metadata(key_id)
            ''')

            # Audit log table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS metadata_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    details TEXT,
                    FOREIGN KEY (file_id) REFERENCES file_metadata(file_id)
                )
            ''')

            conn.commit()

    def _permission_to_str(self, permission: Union[PermissionLevel, str]) -> str:
        """Normalize permission value to its string representation."""

        return PermissionLevel.from_value(permission).value

    def grant_permission(
        self,
        file_id: str,
        user_id: int,
        permission: Union[PermissionLevel, str],
        granted_by: Optional[int] = None
    ) -> bool:
        """Grant a permission to a user for a file."""

        normalized_permission = self._permission_to_str(permission)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            current_time = time.time()
            cursor.execute('''
                INSERT INTO file_permissions (
                    file_id, user_id, permission, granted_by, granted_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, NULL)
                ON CONFLICT(file_id, user_id, permission) DO UPDATE SET
                    granted_by=excluded.granted_by,
                    granted_at=excluded.granted_at,
                    revoked_at=NULL
            ''', (file_id, user_id, normalized_permission, granted_by, current_time))
            conn.commit()
            return True
        except sqlite3.Error as exc:
            print(f"Database error granting permission: {exc}")
            conn.rollback()
            return False
        finally:
            conn.close()

    def revoke_permission(
        self,
        file_id: str,
        user_id: int,
        permission: Optional[Union[PermissionLevel, str]] = None
    ) -> bool:
        """Revoke a previously granted permission."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            params: List[Any] = [time.time(), file_id, user_id]
            query = '''
                UPDATE file_permissions
                SET revoked_at = ?
                WHERE file_id = ? AND user_id = ? AND revoked_at IS NULL
            '''
            if permission is not None:
                query += " AND permission = ?"
                params.append(self._permission_to_str(permission))

            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def has_permission(
        self,
        file_id: str,
        user_id: int,
        permission: Union[PermissionLevel, str]
    ) -> bool:
        """Check if the user currently has the specified permission."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT 1 FROM file_permissions
                WHERE file_id = ? AND user_id = ? AND permission = ? AND revoked_at IS NULL
            ''', (file_id, user_id, self._permission_to_str(permission)))
            return cursor.fetchone() is not None
        finally:
            conn.close()

    def list_permissions(self, file_id: str) -> List[FilePermission]:
        """List all active permissions for a file."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT file_id, user_id, permission, granted_by, granted_at, revoked_at
                FROM file_permissions
                WHERE file_id = ? AND revoked_at IS NULL
            ''', (file_id,))

            rows = cursor.fetchall()
            return [
                FilePermission(
                    file_id=row[0],
                    user_id=row[1],
                    permission=PermissionLevel(row[2]),
                    granted_by=row[3],
                    granted_at=row[4],
                    revoked_at=row[5]
                )
                for row in rows
            ]
        finally:
            conn.close()

    def list_user_permissions(self, user_id: int) -> List[FilePermission]:
        """List all active permissions for a user."""

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT file_id, user_id, permission, granted_by, granted_at, revoked_at
                FROM file_permissions
                WHERE user_id = ? AND revoked_at IS NULL
            ''', (user_id,))

            rows = cursor.fetchall()
            return [
                FilePermission(
                    file_id=row[0],
                    user_id=row[1],
                    permission=PermissionLevel(row[2]),
                    granted_by=row[3],
                    granted_at=row[4],
                    revoked_at=row[5]
                )
                for row in rows
            ]
        finally:
            conn.close()
    def _register_shutdown_cleanup(self) -> None:
        """Register cleanup handler for residual database artifacts."""
        resolved_path = self.db_path.resolve()
        path_key = str(resolved_path)
        if path_key in self._registered_cleanup_paths:
            return
        self._registered_cleanup_paths.add(path_key)
        atexit.register(self._cleanup_residual_files_for_path, resolved_path)

    def _get_connection(self) -> sqlite3.Connection:
        """Return a SQLite connection with hardened PRAGMA settings."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=TRUNCATE")
        conn.execute("PRAGMA secure_delete=ON")
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def cleanup(self) -> None:
        """Remove SQLite residual files after a safe shutdown."""
        self._cleanup_residual_files_for_path(self.db_path.resolve())

    @staticmethod
    def _cleanup_residual_files_for_path(db_path: Path) -> None:
        """Delete WAL, SHM, and backup artifacts for the provided database."""
        parent = db_path.parent
        if not parent.exists():
            return

        residual_suffixes = ("-wal", "-shm")
        backup_patterns = (
            f"{db_path.name}.bak",
            f"{db_path.name}.backup",
            f"{db_path.stem}.bak",
            f"{db_path.stem}.backup",
        )

        for suffix in residual_suffixes:
            candidate = db_path.with_name(db_path.name + suffix)
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
            except OSError:
                pass

        for pattern in backup_patterns:
            for candidate in parent.glob(pattern):
                if candidate == db_path:
                    continue
                try:
                    candidate.unlink()
                except FileNotFoundError:
                    continue
                except OSError:
                    pass

    def add_file_metadata(self, metadata: FileMetadata) -> bool:
        """
        Add file metadata to database

        Args:
            metadata: FileMetadata object

        Returns:
            True if successful
        """
        conn: Optional[sqlite3.Connection] = None
        conn = self._get_connection()
        cursor = conn.cursor()

        self._last_error_message = None

        try:
            with self._pool.connection() as pooled_conn:
                conn = pooled_conn
                cursor = conn.cursor()
                current_time = time.time()

                cursor.execute('''
                    INSERT INTO file_metadata VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                ''', (
                    metadata.file_id,
                    metadata.original_name,
                    metadata.original_size,
                    metadata.encrypted_size,
                    metadata.encryption_timestamp,
                    metadata.encryption_algorithm,
                    metadata.key_id,
                    metadata.iv,
                    metadata.integrity_hash,
                    metadata.compression_used,
                    metadata.compression_algorithm,
                    metadata.shares_total,
                    metadata.shares_threshold,
                    json.dumps(metadata.tags) if metadata.tags else None,
                    json.dumps(metadata.custom_metadata) if metadata.custom_metadata else None,
                    current_time,
                    current_time
                ))

                # Log audit event
                self._log_audit(cursor, metadata.file_id, 'CREATE', {
                    'original_name': metadata.original_name,
                    'size': metadata.original_size
                })

                conn.commit()
                return True

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            if conn and conn.in_transaction:
                conn.rollback()
        except sqlite3.Error as exc:
            self._last_error_message = emit_user_message(
                exc,
                "Unable to add file metadata.",
                logger=logger,
                context="MetadataManager.add_file_metadata",
            )
            conn.rollback()
            return False

    def get_file_metadata(self, file_id: str) -> Optional[FileMetadata]:
        """
        Retrieve file metadata by ID

        Args:
            file_id: File identifier

        Returns:
            FileMetadata object or None if not found
        """
        conn: Optional[sqlite3.Connection] = None

        try:
            with self._pool.connection() as pooled_conn:
                conn = pooled_conn
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM file_metadata WHERE file_id = ?
                ''', (file_id,))

                row = cursor.fetchone()

                if row:
                    metadata = FileMetadata(
                        file_id=row[0],
                        original_name=row[1],
                        original_size=row[2],
                        encrypted_size=row[3],
                        encryption_timestamp=row[4],
                        encryption_algorithm=row[5],
                        key_id=row[6],
                        iv=row[7],
                        integrity_hash=row[8],
                        compression_used=bool(row[9]),
                        compression_algorithm=row[10],
                        shares_total=row[11],
                        shares_threshold=row[12],
                        tags=json.loads(row[13]) if row[13] else None,
                        custom_metadata=json.loads(row[14]) if row[14] else None
                    )

                    # Log access
                    self._log_audit(cursor, file_id, 'READ', {})
                    conn.commit()

                    return metadata

                return None
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM file_metadata WHERE file_id = ?
            ''', (file_id,))

            row = cursor.fetchone()

            if row:
                metadata = self._deserialize_metadata_row(row)

                # Log access
                self._log_audit(cursor, file_id, 'READ', {})
                conn.commit()

                return metadata

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            if conn and conn.in_transaction:
                conn.rollback()
            return None

    def update_file_metadata(self, file_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update file metadata

        Args:
            file_id: File identifier
            updates: Dictionary of fields to update

        Returns:
            True if successful
        """
        if not updates:
            return False

        conn: Optional[sqlite3.Connection] = None
        conn = self._get_connection()
        cursor = conn.cursor()

        self._last_error_message = None

        try:
            with self._pool.connection() as pooled_conn:
                conn = pooled_conn
                cursor = conn.cursor()

                set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
                set_clause += ", updated_at = ?"

                values = list(updates.values()) + [time.time(), file_id]

                cursor.execute(f'''
                    UPDATE file_metadata
                    SET {set_clause}
                    WHERE file_id = ?
                ''', values)

                if cursor.rowcount > 0:
                    self._log_audit(cursor, file_id, 'UPDATE', updates)
                    conn.commit()
                    return True

                return False

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            if conn and conn.in_transaction:
                conn.rollback()
        except sqlite3.Error as exc:
            self._last_error_message = emit_user_message(
                exc,
                "Unable to update file metadata.",
                logger=logger,
                context="MetadataManager.update_file_metadata",
            )
            conn.rollback()
            return False

    def delete_file_metadata(self, file_id: str) -> bool:
        """
        Delete file metadata

        Args:
            file_id: File identifier

        Returns:
            True if successful
        """
        conn: Optional[sqlite3.Connection] = None
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            with self._pool.connection() as pooled_conn:
                conn = pooled_conn
                cursor = conn.cursor()

                # Log deletion before removing
                self._log_audit(cursor, file_id, 'DELETE', {})

                cursor.execute('''
                    DELETE FROM file_metadata WHERE file_id = ?
                ''', (file_id,))

                conn.commit()
                return cursor.rowcount > 0

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            if conn and conn.in_transaction:
                conn.rollback()
            return False

    def search_files(self,
                    name_pattern: Optional[str] = None,
                    tags: Optional[List[str]] = None,
                    min_size: Optional[int] = None,
                    max_size: Optional[int] = None,
                    start_date: Optional[float] = None,
                    end_date: Optional[float] = None,
                    limit: int = 100) -> List[FileMetadata]:
        """
        Search for files matching criteria

        Args:
            name_pattern: SQL LIKE pattern for name matching
            tags: List of tags (match any)
            min_size: Minimum file size
            max_size: Maximum file size
            start_date: Start timestamp
            end_date: End timestamp
            limit: Maximum results to return

        Returns:
            List of matching FileMetadata objects
        """
        try:
            with self._pool.connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM file_metadata WHERE 1=1"
                params: List[Any] = []

                if name_pattern:
                    query += " AND original_name LIKE ?"
                    params.append(name_pattern)

                if min_size is not None:
                    query += " AND original_size >= ?"
                    params.append(min_size)

                if max_size is not None:
                    query += " AND original_size <= ?"
                    params.append(max_size)

                if start_date is not None:
                    query += " AND encryption_timestamp >= ?"
                    params.append(start_date)

                if end_date is not None:
                    query += " AND encryption_timestamp <= ?"
                    params.append(end_date)

                query += " ORDER BY encryption_timestamp DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)

                results: List[FileMetadata] = []
                for row in cursor.fetchall():
                    metadata = FileMetadata(
                        file_id=row[0],
                        original_name=row[1],
                        original_size=row[2],
                        encrypted_size=row[3],
                        encryption_timestamp=row[4],
                        encryption_algorithm=row[5],
                        key_id=row[6],
                        iv=row[7],
                        integrity_hash=row[8],
                        compression_used=bool(row[9]),
                        compression_algorithm=row[10],
                        shares_total=row[11],
                        shares_threshold=row[12],
                        tags=json.loads(row[13]) if row[13] else None,
                        custom_metadata=json.loads(row[14]) if row[14] else None
                    )

                    if tags and metadata.tags:
                        if any(tag in metadata.tags for tag in tags):
                            results.append(metadata)
                    elif not tags:
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            limit, _ = self._sanitize_pagination(limit, 0)

            query = "SELECT * FROM file_metadata WHERE 1=1"
            params = []

            if name_pattern:
                query += " AND original_name LIKE ?"
                params.append(name_pattern)

            if min_size is not None:
                query += " AND original_size >= ?"
                params.append(min_size)

            if max_size is not None:
                query += " AND original_size <= ?"
                params.append(max_size)

            if start_date is not None:
                query += " AND encryption_timestamp >= ?"
                params.append(start_date)

            if end_date is not None:
                query += " AND encryption_timestamp <= ?"
                params.append(end_date)

            query += " ORDER BY encryption_timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)

            results = []
            for row in cursor.fetchall():
                metadata = self._deserialize_metadata_row(row)

                # Filter by tags if specified
                if tags and metadata.tags:
                    if any(tag in metadata.tags for tag in tags):
                        results.append(metadata)

                return results

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def search_metadata(self,
                        criteria: Optional[Dict[str, Any]] = None,
                        sort_by: str = "encryption_timestamp",
                        sort_direction: str = "desc",
                        limit: int = 100,
                        offset: int = 0) -> List[FileMetadata]:
        """Search metadata with secure filtering and sorting.

        Args:
            criteria: Dictionary of search criteria.
            sort_by: Field to sort by (whitelisted).
            sort_direction: Sort direction (asc or desc).
            limit: Maximum number of results to return.
            offset: Number of records to skip.

        Returns:
            List of FileMetadata objects.
        """
        criteria = criteria or {}

        allowed_sort_fields = {
            "file_id": "file_id",
            "original_name": "original_name",
            "original_size": "original_size",
            "encrypted_size": "encrypted_size",
            "encryption_timestamp": "encryption_timestamp",
            "encryption_algorithm": "encryption_algorithm",
            "key_id": "key_id",
            "created_at": "created_at",
            "updated_at": "updated_at"
        }
        allowed_directions = {"asc": "ASC", "desc": "DESC"}

        if sort_by not in allowed_sort_fields:
            raise ValueError(f"Invalid sort field: {sort_by}")

        direction_key = sort_direction.lower()
        if direction_key not in allowed_directions:
            raise ValueError(f"Invalid sort direction: {sort_direction}")

        limit, offset = self._sanitize_pagination(limit, offset)

        where_clauses = []
        params: List[Any] = []

        if "original_name" in criteria:
            where_clauses.append("original_name = ?")
            params.append(criteria["original_name"])

        if "name_pattern" in criteria:
            where_clauses.append("original_name LIKE ?")
            params.append(criteria["name_pattern"])

        if "key_id" in criteria:
            where_clauses.append("key_id = ?")
            params.append(criteria["key_id"])

        if "encryption_algorithm" in criteria:
            where_clauses.append("encryption_algorithm = ?")
            params.append(criteria["encryption_algorithm"])

        if "min_size" in criteria:
            where_clauses.append("original_size >= ?")
            params.append(criteria["min_size"])

        if "max_size" in criteria:
            where_clauses.append("original_size <= ?")
            params.append(criteria["max_size"])

        if "start_date" in criteria:
            where_clauses.append("encryption_timestamp >= ?")
            params.append(criteria["start_date"])

        if "end_date" in criteria:
            where_clauses.append("encryption_timestamp <= ?")
            params.append(criteria["end_date"])

        if "tags" in criteria:
            tags = criteria["tags"]
            if isinstance(tags, str):
                tags = [tags]
            for tag in tags:
                where_clauses.append("tags LIKE ?")
                params.append(f"%{tag}%")

        query = "SELECT * FROM file_metadata"
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)

        order_clause = f" ORDER BY {allowed_sort_fields[sort_by]} {allowed_directions[direction_key]}"
        query += order_clause
        query += " LIMIT ? OFFSET ?"

        params.extend([limit, offset])

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [self._deserialize_metadata_row(row) for row in rows]
        finally:
            conn.close()

    def list_all_files(self, limit: int = 100, offset: int = 0) -> List[FileMetadata]:
        """
        List all files with pagination

        Args:
            limit: Maximum results
            offset: Offset for pagination

        Returns:
            List of FileMetadata objects
        """
        try:
            with self._pool.connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT * FROM file_metadata
                    ORDER BY encryption_timestamp DESC
                    LIMIT ? OFFSET ?
                ''', (limit, offset))

                results: List[FileMetadata] = []
                for row in cursor.fetchall():
                    metadata = FileMetadata(
                        file_id=row[0],
                        original_name=row[1],
                        original_size=row[2],
                        encrypted_size=row[3],
                        encryption_timestamp=row[4],
                        encryption_algorithm=row[5],
                        key_id=row[6],
                        iv=row[7],
                        integrity_hash=row[8],
                        compression_used=bool(row[9]),
                        compression_algorithm=row[10],
                        shares_total=row[11],
                        shares_threshold=row[12],
                        tags=json.loads(row[13]) if row[13] else None,
                        custom_metadata=json.loads(row[14]) if row[14] else None
                    )
                    results.append(metadata)
        conn = self._get_connection()
        limit, offset = self._sanitize_pagination(limit, offset)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM file_metadata
                ORDER BY encryption_timestamp DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))

            results = []
            for row in cursor.fetchall():
                results.append(self._deserialize_metadata_row(row))

                return results

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return []

    def _sanitize_pagination(self, limit: Any, offset: Any, max_limit: int = 500) -> Tuple[int, int]:
        """Validate and sanitize pagination parameters."""
        if limit is None:
            limit_value = min(100, max_limit)
        else:
            if not isinstance(limit, int):
                try:
                    limit_value = int(limit)
                except (TypeError, ValueError):
                    raise ValueError("Limit must be an integer")
            else:
                limit_value = limit

        if limit_value < 1:
            raise ValueError("Limit must be greater than zero")

        if limit_value > max_limit:
            limit_value = max_limit

        if offset is None:
            offset_value = 0
        else:
            if not isinstance(offset, int):
                try:
                    offset_value = int(offset)
                except (TypeError, ValueError):
                    raise ValueError("Offset must be an integer")
            else:
                offset_value = offset

        if offset_value < 0:
            raise ValueError("Offset must be non-negative")

        return limit_value, offset_value

    def _deserialize_metadata_row(self, row: Tuple[Any, ...]) -> FileMetadata:
        """Convert a database row into a FileMetadata object."""
        return FileMetadata(
            file_id=row[0],
            original_name=row[1],
            original_size=row[2],
            encrypted_size=row[3],
            encryption_timestamp=row[4],
            encryption_algorithm=row[5],
            key_id=row[6],
            iv=row[7],
            integrity_hash=row[8],
            compression_used=bool(row[9]),
            compression_algorithm=row[10],
            shares_total=row[11],
            shares_threshold=row[12],
            tags=json.loads(row[13]) if row[13] else None,
            custom_metadata=json.loads(row[14]) if row[14] else None
        )

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get metadata statistics

        Returns:
            Dictionary with statistics
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            with self._pool.connection() as conn:
                cursor = conn.cursor()
                stats: Dict[str, Any] = {}

                cursor.execute("SELECT COUNT(*) FROM file_metadata")
                stats['total_files'] = cursor.fetchone()[0]

                cursor.execute("SELECT SUM(original_size) FROM file_metadata")
                stats['total_original_size'] = cursor.fetchone()[0] or 0

                cursor.execute("SELECT SUM(encrypted_size) FROM file_metadata")
                stats['total_encrypted_size'] = cursor.fetchone()[0] or 0

                cursor.execute('''
                    SELECT COUNT(*) FROM file_metadata WHERE compression_used = 1
                ''')
                stats['files_compressed'] = cursor.fetchone()[0]

                cursor.execute('''
                    SELECT encryption_algorithm, COUNT(*)
                    FROM file_metadata
                    GROUP BY encryption_algorithm
                ''')
                stats['algorithm_usage'] = dict(cursor.fetchall())

                return stats

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return {}

    def _log_audit(self, cursor, file_id: str, operation: str, details: Dict[str, Any]):
        """
        Log audit event

        Args:
            cursor: Database cursor
            file_id: File identifier
            operation: Operation type
            details: Operation details
        """
        cursor.execute('''
            INSERT INTO metadata_audit (file_id, operation, timestamp, details)
            VALUES (?, ?, ?, ?)
        ''', (file_id, operation, time.time(), json.dumps(details)))

    def close(self) -> None:
        """Release all connections held by the metadata manager."""

        if hasattr(self, "_pool"):
            self._pool.close()

    def export_metadata(self, output_path: Path) -> bool:
        """
        Export all metadata to JSON file

        Args:
            output_path: Path to output file

        Returns:
            True if successful
        """
        self._last_error_message = None

        try:
            files = self.list_all_files(limit=10000)

            export_data = {
                'version': '1.0',
                'export_timestamp': time.time(),
                'total_files': len(files),
                'files': []
            }

            for metadata in files:
                export_data['files'].append({
                    'file_id': metadata.file_id,
                    'original_name': metadata.original_name,
                    'original_size': metadata.original_size,
                    'encrypted_size': metadata.encrypted_size,
                    'encryption_timestamp': metadata.encryption_timestamp,
                    'encryption_algorithm': metadata.encryption_algorithm,
                    'key_id': metadata.key_id,
                    'iv': metadata.iv.hex() if isinstance(metadata.iv, bytes) else metadata.iv,
                    'integrity_hash': metadata.integrity_hash,
                    'compression_used': metadata.compression_used,
                    'compression_algorithm': metadata.compression_algorithm,
                    'shares_total': metadata.shares_total,
                    'shares_threshold': metadata.shares_threshold,
                    'tags': metadata.tags,
                    'custom_metadata': metadata.custom_metadata
                })

            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            return True

        except Exception as exc:
            self._last_error_message = emit_user_message(
                exc,
                "Unable to export metadata.",
                logger=logger,
                context="MetadataManager.export_metadata",
            )
            return False
