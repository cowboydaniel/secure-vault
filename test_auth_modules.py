"""Unit tests for SecureVault authentication components."""

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime
from pathlib import Path

from auth_database import AuthDatabase
from auth_manager import (
    AuthManager,
    AuthSession,
    InvalidCredentialsError,
    SessionExpiredError,
)
from instance_guard import InstanceGuard, TamperDetectedError
from pin_manager import PINManager, PINValidationError
from rate_limiter import AccountLockedError, RateLimitError
from user_manager import UserManager, UserExistsError


class AuthenticationTestCase(unittest.TestCase):
    """Test harness that provisions an isolated authentication database."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = os.path.join(self.temp_dir.name, "state")
        self._prev_state_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        os.environ["SECURE_VAULT_STATE_DIR"] = self.state_dir
        self.db_path = os.path.join(self.temp_dir.name, "users.db")
        self.db = AuthDatabase(db_path=self.db_path)
        db_path = os.path.join(self.temp_dir.name, "users.db")
        self.db = AuthDatabase(db_path=db_path)
        self.auth_manager = AuthManager(db=self.db)
        self.user_manager: UserManager = self.auth_manager.user_manager

    def tearDown(self) -> None:  # pragma: no cover - cleanup
        if self._prev_state_dir is not None:
            os.environ["SECURE_VAULT_STATE_DIR"] = self._prev_state_dir
        else:
            os.environ.pop("SECURE_VAULT_STATE_DIR", None)
        self.temp_dir.cleanup()

    def test_pin_manager_round_trip(self) -> None:
        """PIN manager should encrypt and verify master keys reliably."""

        manager = PINManager()
        pin = "758321"
        salt = manager.generate_salt()
        derived = manager.derive_key_from_pin(pin, salt)
        master_key = manager.generate_master_key()
        associated_data = b"test@example.commaster_key"

        encrypted = manager.encrypt_master_key(master_key, derived, associated_data)
        decrypted = manager.decrypt_master_key(encrypted, derived, associated_data)
        verification_marker = manager.create_verification_marker(master_key, b"verification")

        self.assertEqual(master_key, decrypted)
        self.assertTrue(manager.verify_master_key(master_key, verification_marker, b"verification"))

        with self.assertRaises(PINValidationError):
            manager.validate_pin_format("123456")

    def test_end_to_end_auth_flow(self) -> None:
        """Creating a user should allow successful PIN authentication."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "839201"

        user_id = self.user_manager.create_user(email=email, password=password, pin=pin)
        self.assertIsInstance(user_id, int)

        db_user = self.db.get_user_by_id(user_id)
        self.assertIsNotNone(db_user.email_lookup_hash)
        self.assertIsNotNone(db_user.email_salt)
        self.assertEqual(16, len(db_user.email_salt))
        self.assertEqual('argon2id', db_user.password_kdf)
        self.assertIn('time_cost', db_user.password_kdf_metadata)

        session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)
        self.assertIsNotNone(session)
        self.assertEqual(user_id, session.user_id)
        self.assertEqual(32, len(session.get_master_key()))

        credentials = self.db.get_credentials(user_id)
        self.assertEqual('argon2id', credentials.kdf_algorithm)
        self.assertIn('memory_cost', credentials.kdf_metadata)

        # Session should remain retrievable until logout
        retrieved = self.auth_manager.get_session(session.session_id)
        self.assertIsNotNone(retrieved)

        stored_session = self.db.get_session(session.session_id)
        self.assertIsNotNone(stored_session)
        self.assertNotEqual(stored_session.session_id, session.session_id)
        self.assertEqual(64, len(stored_session.session_id))
        self.assertNotIn('-', stored_session.session_id)

        self.auth_manager.logout(session.session_id)
        self.assertIsNone(self.auth_manager.get_session(session.session_id))

    def test_concurrent_master_key_access_blocks_logout(self) -> None:
        """Master key reads and logout operations should be serialized per session."""

        email = "charlie@example.com"
        password = "C0ncurrentPass!"
        pin = "123789"

        self.user_manager.create_user(email=email, password=password, pin=pin)
        session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)

        access_started = threading.Event()
        release_access = threading.Event()
        logout_completed = threading.Event()
        results = []
        errors = []

        original_get_master_key = AuthSession.get_master_key

        def instrumented_get_master_key(self: AuthSession) -> bytes:
            with self._lock:
                access_started.set()
                if not release_access.wait(timeout=2):
                    raise TimeoutError("Timed out waiting to resume master key access")

                if self.is_expired():
                    raise SessionExpiredError("Session has expired")

                if self._master_key is None:
                    raise SessionExpiredError("Session has ended")

                self.last_activity = datetime.now()
                return bytes(self._master_key)

        AuthSession.get_master_key = instrumented_get_master_key  # type: ignore[assignment]
        self.addCleanup(lambda: setattr(AuthSession, "get_master_key", original_get_master_key))
        self.addCleanup(release_access.set)

        def read_master_key() -> None:
            try:
                results.append(session.get_master_key())
            except Exception as exc:  # pragma: no cover - defensive
                errors.append(exc)

        key_thread = threading.Thread(target=read_master_key)
        key_thread.start()

        self.assertTrue(access_started.wait(timeout=2))

        def perform_logout() -> None:
            self.auth_manager.logout(session.session_id)
            logout_completed.set()

        logout_thread = threading.Thread(target=perform_logout)
        logout_thread.start()

        self.assertFalse(logout_completed.wait(timeout=0.2))

        release_access.set()

        key_thread.join(timeout=2)
        logout_thread.join(timeout=2)

        self.assertFalse(key_thread.is_alive())
        self.assertFalse(logout_thread.is_alive())

        self.assertTrue(logout_completed.is_set())
        self.assertFalse(errors)
        self.assertEqual(1, len(results))
        self.assertEqual(32, len(results[0]))
        self.assertIsNone(self.auth_manager.get_session(session.session_id))

    def test_rate_limiter_enforces_lockout(self) -> None:
        """Repeated invalid attempts trigger an account lockout."""

        email = "bob@example.com"
        password = "AnotherStr0ngPass!"
        pin = "675849"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        # Speed up the lockout for testing purposes
        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 3
        limiter.config.exponential_backoff = False

        for _ in range(limiter.config.max_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(email=email, pin="000000")

        with self.assertRaises(AccountLockedError):
            self.auth_manager.authenticate_with_pin(email=email, pin="000000")

    def test_prevents_multiple_accounts(self) -> None:
        """Only a single owner account may be provisioned."""

        email = "owner@example.com"
        password = "Secur3OwnerPass!"
        pin = "746291"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        with self.assertRaises(UserExistsError):
            self.user_manager.create_user(
                email="second@example.com",
                password="AnotherStrongPass1!",
                pin="839120",
            )

    def test_global_rate_limit_blocks_unknown_email(self) -> None:
        """Repeated failures for the same email trigger a cooldown."""

        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 50
        limiter.config.max_global_attempts = 10
        limiter.config.global_window_seconds = 600
        limiter.config.max_email_attempts = 2
        limiter.config.email_window_seconds = 3600

        target_email = "nobody@example.com"

        for _ in range(limiter.config.max_email_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(email=target_email, pin="000000")

        with self.assertRaises(RateLimitError):
            self.auth_manager.authenticate_with_pin(email=target_email, pin="000000")

    def test_lockdown_when_database_missing(self) -> None:
        """Deleting the authentication database triggers tamper lockdown."""

        self.user_manager.create_user(
            email="alice@example.com",
            password="Sup3rSecurePass!",
            pin="839201",
        )

        self.db.close()
        os.remove(self.db_path)

        with self.assertRaises(TamperDetectedError):
            AuthDatabase(db_path=self.db_path)

    def test_guard_state_reversion_detected(self) -> None:
        """Reverting the guard state to pending should be treated as tampering."""

        self.user_manager.create_user(
            email="owner@example.com",
            password="Secur3OwnerPass!",
            pin="746291",
        )

        state_path = Path(self.state_dir) / InstanceGuard.STATE_FILENAME
        with state_path.open("r", encoding="utf-8") as handle:
            state_data = json.load(handle)

        state_data["status"] = "pending"
        state_data.pop("locked_at", None)
        state_data.pop("lock_reason", None)

        tmp_path = state_path.with_suffix(".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(state_data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, state_path)
        os.chmod(state_path, 0o600)

        self.db.close()
        os.remove(self.db_path)

        with self.assertRaises(TamperDetectedError):
            AuthDatabase(db_path=self.db_path)



if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
