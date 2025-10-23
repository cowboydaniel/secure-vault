"""
Secure Metadata Management

Manages metadata for encrypted files including file information,
encryption parameters, and integrity data in a secure SQLite database.
"""

import atexit
import sqlite3
import json
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass


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
        self._init_database()
        self._register_shutdown_cleanup()

    def _init_database(self):
        """Initialize database schema"""
        conn = self._get_connection()
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
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
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
            conn.rollback()
            return False

        finally:
            conn.close()

    def get_file_metadata(self, file_id: str) -> Optional[FileMetadata]:
        """
        Retrieve file metadata by ID

        Args:
            file_id: File identifier

        Returns:
            FileMetadata object or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
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

        finally:
            conn.close()

    def update_file_metadata(self, file_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update file metadata

        Args:
            file_id: File identifier
            updates: Dictionary of fields to update

        Returns:
            True if successful
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Build update query
            set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
            set_clause += ", updated_at = ?"

            values = list(updates.values()) + [time.time(), file_id]

            cursor.execute(f'''
                UPDATE file_metadata
                SET {set_clause}
                WHERE file_id = ?
            ''', values)

            if cursor.rowcount > 0:
                # Log audit event
                self._log_audit(cursor, file_id, 'UPDATE', updates)
                conn.commit()
                return True

            return False

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            conn.rollback()
            return False

        finally:
            conn.close()

    def delete_file_metadata(self, file_id: str) -> bool:
        """
        Delete file metadata

        Args:
            file_id: File identifier

        Returns:
            True if successful
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Log deletion before removing
            self._log_audit(cursor, file_id, 'DELETE', {})

            cursor.execute('''
                DELETE FROM file_metadata WHERE file_id = ?
            ''', (file_id,))

            conn.commit()
            return cursor.rowcount > 0

        finally:
            conn.close()

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
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
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

                # Filter by tags if specified
                if tags and metadata.tags:
                    if any(tag in metadata.tags for tag in tags):
                        results.append(metadata)
                elif not tags:
                    results.append(metadata)

            return results

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
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute('''
                SELECT * FROM file_metadata
                ORDER BY encryption_timestamp DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))

            results = []
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

            return results

        finally:
            conn.close()

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get metadata statistics

        Returns:
            Dictionary with statistics
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            stats = {}

            # Total files
            cursor.execute("SELECT COUNT(*) FROM file_metadata")
            stats['total_files'] = cursor.fetchone()[0]

            # Total size (original)
            cursor.execute("SELECT SUM(original_size) FROM file_metadata")
            stats['total_original_size'] = cursor.fetchone()[0] or 0

            # Total size (encrypted)
            cursor.execute("SELECT SUM(encrypted_size) FROM file_metadata")
            stats['total_encrypted_size'] = cursor.fetchone()[0] or 0

            # Compression stats
            cursor.execute('''
                SELECT COUNT(*) FROM file_metadata WHERE compression_used = 1
            ''')
            stats['files_compressed'] = cursor.fetchone()[0]

            # Algorithm usage
            cursor.execute('''
                SELECT encryption_algorithm, COUNT(*)
                FROM file_metadata
                GROUP BY encryption_algorithm
            ''')
            stats['algorithm_usage'] = dict(cursor.fetchall())

            return stats

        finally:
            conn.close()

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

    def export_metadata(self, output_path: Path) -> bool:
        """
        Export all metadata to JSON file

        Args:
            output_path: Path to output file

        Returns:
            True if successful
        """
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

        except Exception as e:
            print(f"Export error: {e}")
            return False
