"""Integration tests for hardened SQLite configurations."""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Optional

from auth_database import AuthDatabase
from metadata_manager import MetadataManager


class DatabaseSecurityTests(unittest.TestCase):
    """Validate SQLite PRAGMA hardening and cleanup procedures."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base_path = Path(self.temp_dir.name)

    def test_metadata_manager_pragmas(self) -> None:
        db_path = self.base_path / "metadata.db"
        manager = MetadataManager(db_path=str(db_path))

        conn = manager._get_connection()
        try:
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            secure_delete = conn.execute("PRAGMA secure_delete").fetchone()[0]
        finally:
            conn.close()

        self.assertEqual("TRUNCATE", str(journal_mode).upper())
        self.assertIn(str(secure_delete).lower(), {"1", "on", "true"})

    def test_metadata_manager_cleanup_removes_residual_files(self) -> None:
        db_path = self.base_path / "metadata_cleanup.db"
        manager = MetadataManager(db_path=str(db_path))

        wal_path = Path(f"{db_path}-wal")
        shm_path = Path(f"{db_path}-shm")
        backup_path = db_path.with_name(db_path.name + ".bak")

        for path in (wal_path, shm_path, backup_path):
            path.touch()
            self.assertTrue(path.exists())

        manager.cleanup()

        for path in (wal_path, shm_path, backup_path):
            self.assertFalse(path.exists())

    def test_auth_database_pragmas(self) -> None:
        db_path = self.base_path / "users.db"
        state_dir = self.base_path / "state"
        state_dir.mkdir(parents=True, exist_ok=True)

        previous_state_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        previous_wrap_secret = os.environ.get("SECURE_VAULT_GUARD_WRAP_SECRET")
        os.environ["SECURE_VAULT_STATE_DIR"] = str(state_dir)
        os.environ["SECURE_VAULT_GUARD_WRAP_SECRET"] = "db-test-wrap"
        self.addCleanup(self._restore_env, previous_state_dir, previous_wrap_secret)

        db = AuthDatabase(db_path=str(db_path))
        conn = db._get_connection()
        try:
            journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            secure_delete = conn.execute("PRAGMA secure_delete").fetchone()[0]
        finally:
            conn.close()

        db.close()

        self.assertEqual("TRUNCATE", str(journal_mode).upper())
        self.assertIn(str(secure_delete).lower(), {"1", "on", "true"})

    def test_auth_database_cleanup_removes_residual_files(self) -> None:
        db_path = self.base_path / "cleanup_users.db"
        state_dir = self.base_path / "cleanup_state"
        state_dir.mkdir(parents=True, exist_ok=True)

        previous_state_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        previous_wrap_secret = os.environ.get("SECURE_VAULT_GUARD_WRAP_SECRET")
        os.environ["SECURE_VAULT_STATE_DIR"] = str(state_dir)
        os.environ["SECURE_VAULT_GUARD_WRAP_SECRET"] = "db-test-wrap"
        self.addCleanup(self._restore_env, previous_state_dir, previous_wrap_secret)

        db = AuthDatabase(db_path=str(db_path))

        wal_path = Path(f"{db_path}-wal")
        shm_path = Path(f"{db_path}-shm")
        backup_path = db_path.with_name(db_path.name + ".bak")

        for path in (wal_path, shm_path, backup_path):
            path.touch()
            self.assertTrue(path.exists())

        db.close()

        for path in (wal_path, shm_path, backup_path):
            self.assertFalse(path.exists())

    @staticmethod
    def _restore_env(previous_state_dir: Optional[str], previous_wrap: Optional[str]) -> None:
        if previous_state_dir is None:
            os.environ.pop("SECURE_VAULT_STATE_DIR", None)
        else:
            os.environ["SECURE_VAULT_STATE_DIR"] = previous_state_dir

        if previous_wrap is None:
            os.environ.pop("SECURE_VAULT_GUARD_WRAP_SECRET", None)
        else:
            os.environ["SECURE_VAULT_GUARD_WRAP_SECRET"] = previous_wrap


if __name__ == "__main__":  # pragma: no cover - manual execution
    unittest.main()
