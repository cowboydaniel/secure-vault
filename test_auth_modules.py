"""Unit tests for SecureVault authentication components."""

import concurrent.futures
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime
import time
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from auth_database import AuthDatabase
from auth_manager import (
    AuthManager,
    AuthSession,
    InvalidCredentialsError,
    SessionExpiredError,
    InvalidCredentialsError,
    SessionExpiredError,
from auth_manager import AuthManager, InvalidCredentialsError, SessionExpiredError
from auth_manager import (
    AuthManager,
    InvalidCredentialsError,
    SessionHijackingError,
)
from instance_guard import InstanceGuard, TamperDetectedError
from pin_manager import PINManager, PINValidationError
from rate_limiter import AccountLockedError, RateLimitError
from user_manager import UserManager, UserExistsError, ValidationError
import os
import tempfile
import unittest

from auth_database import AuthDatabase
from auth_manager import AuthManager, InvalidCredentialsError
from instance_guard import TamperDetectedError
from pin_manager import PINManager, PINValidationError
from pin_manager import PINManager, PINValidationError, PINPolicy
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
        self.db = AuthDatabase(db_path=self.db_path, pool_size=3)
        self.db = AuthDatabase(db_path=self.db_path)
        self.auth_manager = AuthManager(db=self.db)
        self.user_manager: UserManager = self.auth_manager.user_manager

    def tearDown(self) -> None:  # pragma: no cover - cleanup
        self.auth_manager.close()
        self.db.close()
        if self._prev_state_dir is not None:
            os.environ["SECURE_VAULT_STATE_DIR"] = self._prev_state_dir
        else:
            os.environ.pop("SECURE_VAULT_STATE_DIR", None)
        self.temp_dir.cleanup()

    def test_pin_manager_round_trip(self) -> None:
        """PIN manager should encrypt and verify master keys reliably."""

        manager = PINManager()
        pin = "75832164"
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
            manager.validate_pin_format("1234567")

    def test_configurable_alphanumeric_pin_policy(self) -> None:
        """PIN policy can require alphanumeric PINs when configured."""

        policy = PINPolicy(min_length=10, require_letter=True)
        manager = PINManager(pin_policy=policy)

        # Valid: meets length, includes both letters and digits
        manager.validate_pin_format("VaultKey90")

        # Invalid: lacks alphabetic characters required by policy
        with self.assertRaises(PINValidationError):
            manager.validate_pin_format("1234567890")

    def test_pin_pattern_validation(self) -> None:
        """Pattern-based PINs should be rejected with validation errors."""

        manager = PINManager()
        invalid_pins = ["010190", "20240101", "555120"]

        for candidate in invalid_pins:
            with self.assertRaises(PINValidationError):
                manager.validate_pin_format(candidate)

    def test_end_to_end_auth_flow(self) -> None:
        """Creating a user should allow successful PIN authentication."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "83920174"

        user_id = self.user_manager.create_user(email=email, password=password, pin=pin)
        self.assertIsInstance(user_id, int)

        db_user = self.db.get_user_by_id(user_id)
        self.assertIsNotNone(db_user.email_lookup_hash)
        self.assertIsNotNone(db_user.email_salt)
        self.assertEqual(16, len(db_user.email_salt))
        self.assertEqual('argon2id', db_user.password_kdf)
        self.assertIn('time_cost', db_user.password_kdf_metadata)

        login_ip = " 198.51.100.5 "
        login_user_agent = " SecureVaultTest/1.0 "
        session = self.auth_manager.authenticate_with_pin(
            email=email,
            pin=pin,
            ip_address=login_ip,
            user_agent=login_user_agent,
        )
        self.assertIsNotNone(session)
        self.assertEqual(user_id, session.user_id)

        with session.master_key() as buffer:
            self.assertEqual(32, len(buffer))
            snapshot = bytes(buffer)

        self.assertEqual(32, len(snapshot))
        self.assertTrue(all(b == 0 for b in buffer))
        self.assertTrue(session.has_master_key())

        credentials = self.db.get_credentials(user_id)
        self.assertEqual('argon2id', credentials.kdf_algorithm)
        self.assertIn('memory_cost', credentials.kdf_metadata)

        # Session should remain retrievable until logout
        normalized_ip = "198.51.100.5"
        normalized_user_agent = "SecureVaultTest/1.0"
        retrieved = self.auth_manager.get_session(
            session.session_id,
            normalized_ip,
            normalized_user_agent,
        )
        self.assertIsNotNone(retrieved)

        stored_session = self.db.get_session(session.session_id)
        self.assertIsNotNone(stored_session)
        self.assertNotEqual(stored_session.session_id, session.session_id)
        self.assertEqual(64, len(stored_session.session_id))
        self.assertNotIn('-', stored_session.session_id)
        self.assertEqual(normalized_ip, stored_session.ip_address)
        self.assertEqual(normalized_user_agent, stored_session.user_agent)

        self.auth_manager.logout(session.session_id)
        self.assertIsNone(self.auth_manager.get_session(session.session_id))
        self.assertFalse(session.has_master_key())

    def test_session_secret_zeroized_after_logout(self) -> None:
        """Logging out should wipe the in-memory session secret."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "839201"

        self.user_manager.create_user(email=email, password=password, pin=pin)
        session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)

        with session.master_key() as buffer:
            preview = bytes(buffer)

        self.assertEqual(32, len(preview))
        self.assertTrue(session.has_master_key())

        self.auth_manager.logout(session.session_id)

        self.assertFalse(session.has_master_key())
        with self.assertRaises(SessionExpiredError):
            with session.master_key():
                pass
        self.assertIsNone(
            self.auth_manager.get_session(
                session.session_id,
                normalized_ip,
                normalized_user_agent,
            )
        )

    def test_detects_session_client_metadata_mismatch(self) -> None:
        """Session retrieval should fail if client metadata changes."""

        email = "carol@example.com"
        password = "Sup3rSecurePass!"
        pin = "123789"
        ip_address = "203.0.113.9"
        user_agent = "SecureVaultTest/2.0"

        self.user_manager.create_user(email=email, password=password, pin=pin)
        session = self.auth_manager.authenticate_with_pin(
            email=email,
            pin=pin,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Baseline retrieval succeeds with matching metadata
        self.assertIsNotNone(
            self.auth_manager.get_session(session.session_id, ip_address, user_agent)
        )

        # Mismatched metadata should trigger hijacking detection
        with self.assertRaises(SessionHijackingError):
            self.auth_manager.get_session(
                session.session_id,
                "198.51.100.23",
                user_agent,
            )

        # Session should no longer be retrievable after hijacking detection
        self.assertIsNone(
            self.auth_manager.get_session(
                session.session_id,
                ip_address,
                user_agent,
            )
        )

    def test_get_master_key_rechecks_expiration_under_contention(self) -> None:
        """Concurrent expiration should prevent key access and avoid activity updates."""

        email = "carol@example.com"
        password = "Sup3rSecurePass!"
        pin = "123789"

        self.user_manager.create_user(email=email, password=password, pin=pin)
        session = self.auth_manager.authenticate_with_pin(email=email, pin=pin)

        previous_activity = session.last_activity
        initial_time = previous_activity
        future_time = previous_activity + timedelta(seconds=30)
        expired_time = future_time + timedelta(seconds=1)
        session.expires_at = future_time

        first_check_event = threading.Event()
        proceed_event = threading.Event()
        errors = []

        def fake_now():
            if not first_check_event.is_set():
                first_check_event.set()
                proceed_event.wait(timeout=2)
                return initial_time
            return expired_time

        def access_master_key():
            try:
                session.get_master_key()
            except SessionExpiredError as exc:  # pragma: no cover - thread error path
                errors.append(exc)

        def expire_session():
            if first_check_event.wait(timeout=2):
                session.expires_at = initial_time
                proceed_event.set()
            else:  # pragma: no cover - diagnostic fallback
                proceed_event.set()

        with mock.patch("auth_manager.datetime") as mock_datetime:
            mock_datetime.now.side_effect = fake_now

            worker = threading.Thread(target=access_master_key)
            expirer = threading.Thread(target=expire_session)
            worker.start()
            expirer.start()
            worker.join(timeout=5)
            expirer.join(timeout=5)

        self.assertFalse(worker.is_alive())
        self.assertFalse(expirer.is_alive())
        self.assertTrue(errors)
        self.assertIsInstance(errors[0], SessionExpiredError)
        self.assertEqual(previous_activity, session.last_activity)

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
        pin = "67584920"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        # Speed up the lockout for testing purposes
        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 3
        limiter.config.exponential_backoff = False

        for _ in range(limiter.config.max_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(email=email, pin="00000000")

        with self.assertRaises(AccountLockedError):
            self.auth_manager.authenticate_with_pin(email=email, pin="00000000")

    def test_rate_limiter_thread_safety_under_concurrent_failures(self) -> None:
        """Concurrent failed attempts should not trigger race conditions."""

        email = "carol@example.com"
        password = "Thre@dsAreHard1"
        pin = "581932"

        user_id = self.user_manager.create_user(email=email, password=password, pin=pin)

        limiter = self.auth_manager.rate_limiter
        limiter.config.max_attempts = 128
        limiter.config.exponential_backoff = False
        limiter.config.max_global_attempts = 256
        limiter.config.max_email_attempts = 256

        attempt_threads = 24
        barrier = threading.Barrier(attempt_threads + 2)
        unexpected_errors = []
        status_errors = []

        def attempt_authentication() -> None:
            try:
                barrier.wait()
                self.auth_manager.authenticate_with_pin(email=email, pin="000000")
            except InvalidCredentialsError:
                return
            except Exception as exc:  # pragma: no cover - defensive branch
                unexpected_errors.append(exc)

        def poll_lockout_status() -> None:
            try:
                barrier.wait()
            except threading.BrokenBarrierError:  # pragma: no cover - defensive
                return

            for _ in range(attempt_threads * 6):
                try:
                    self.auth_manager.rate_limiter.get_lockout_status(user_id)
                except Exception as exc:  # pragma: no cover - defensive branch
                    status_errors.append(exc)
                    break
                time.sleep(0.001)

        threads = [threading.Thread(target=attempt_authentication) for _ in range(attempt_threads)]
        for thread in threads:
            thread.start()

        status_thread = threading.Thread(target=poll_lockout_status)
        status_thread.start()

        # Release all threads simultaneously
        try:
            barrier.wait()
        except threading.BrokenBarrierError:  # pragma: no cover - defensive
            pass

        for thread in threads:
            thread.join()

        status_thread.join()

        self.assertFalse(unexpected_errors, f"Unexpected exceptions: {unexpected_errors}")
        self.assertFalse(status_errors, f"Status polling errors: {status_errors}")

        user = self.db.get_user_by_id(user_id)
        self.assertIsNotNone(user)
        if user is not None:
            self.assertEqual(attempt_threads, user.failed_attempts)

    def test_prevents_multiple_accounts(self) -> None:
        """Only a single owner account may be provisioned."""

        email = "owner@example.com"
        password = "Secur3OwnerPass!"
        pin = "74629183"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        with self.assertRaises(UserExistsError):
            self.user_manager.create_user(
                email="second@example.com",
                password="AnotherStrongPass1!",
                pin="83912057",
            )

    def test_registration_rejects_invalid_email(self) -> None:
        """Registration should block malformed email addresses."""

        with self.assertRaises(ValidationError):
            self.user_manager.create_user(
                email="invalid-email",
                password="Sup3rSecurePass!",
                pin="839201",
            )

    def test_registration_rejects_homograph_email(self) -> None:
        """Unicode homograph domains are rejected during registration."""

        with self.assertRaises(ValidationError):
            self.user_manager.create_user(
                email="owner@раypal.com",  # Cyrillic characters
                password="Sup3rSecurePass!",
                pin="839201",
            )

    def test_login_rejects_homograph_email_attempt(self) -> None:
        """Authentication should fail for homograph email attempts."""

        email = "alice@example.com"
        password = "Sup3rSecurePass!"
        pin = "839201"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        with self.assertRaises(InvalidCredentialsError):
            self.auth_manager.authenticate_with_pin(email="alice@еxample.com", pin=pin)

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
                self.auth_manager.authenticate_with_pin(email=target_email, pin="00000000")

        with self.assertRaises(RateLimitError):
            self.auth_manager.authenticate_with_pin(email=target_email, pin="00000000")

    def test_aliases_share_device_limits(self) -> None:
        """Email aliases from the same device share throttling state."""

        email = "carol@example.com"
        alias = "carol+spam@example.com"
        password = "ComplexP@ss123!"
        pin = "482951"
        ip_address = "203.0.113.5"
        device_fingerprint = "device-test-001"
        user_agent = "SecureVaultTests/1.0"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        limiter = self.auth_manager.rate_limiter
        limiter.config.max_email_attempts = 2
        limiter.config.email_window_seconds = 600

        for _ in range(limiter.config.max_email_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.auth_manager.authenticate_with_pin(
                    email=alias,
                    pin="000000",
                    ip_address=ip_address,
                    device_fingerprint=device_fingerprint,
                    user_agent=user_agent,
                )

        with self.assertRaises(RateLimitError):
            self.auth_manager.authenticate_with_pin(
                email=email,
                pin=pin,
                ip_address=ip_address,
                device_fingerprint=device_fingerprint,
                user_agent=user_agent,
            )

    def test_lockdown_when_database_missing(self) -> None:
        """Deleting the authentication database triggers tamper lockdown."""

        self.user_manager.create_user(
            email="alice@example.com",
            password="Sup3rSecurePass!",
            pin="83920174",
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
            pin="74629183",
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

    def test_connection_pool_handles_concurrent_usage(self) -> None:
        """Connection pool should safely serve concurrent readers."""

        email = "pool@example.com"
        password = "Str0ngPassword!"
        pin = "123789"

        self.user_manager.create_user(email=email, password=password, pin=pin)

        seen_connections: set[int] = set()
        lock = threading.Lock()

        def query_user_count(_: int) -> int:
            with self.db._pool.connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                count = cursor.fetchone()[0]
                with lock:
                    seen_connections.add(id(conn))
                return count

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(query_user_count, range(24)))

        self.assertTrue(all(result >= 1 for result in results))
        self.assertLessEqual(len(seen_connections), self.db._pool.max_size)
    def test_missing_guard_state_with_existing_db_triggers_lockdown(self) -> None:
        """Removing guard state while keeping the database should lock down."""

        self.user_manager.create_user(
            email="owner@example.com",
            password="Secur3OwnerPass!",
            pin="746291",
        )

        state_path = Path(self.state_dir) / InstanceGuard.STATE_FILENAME
        state_path.unlink()

        self.db.close()

        with self.assertRaises(TamperDetectedError):
            AuthDatabase(db_path=self.db_path)

    def test_missing_guard_state_and_database_detected(self) -> None:
        """Removing both the database and guard state trips tamper detection."""

        self.user_manager.create_user(
            email="owner@example.com",
            password="Secur3OwnerPass!",
            pin="746291",
        )

        state_path = Path(self.state_dir) / InstanceGuard.STATE_FILENAME
        marker_path = Path(self.state_dir) / InstanceGuard.MARKER_FILENAME
        self.assertTrue(marker_path.exists())

        self.db.close()
        os.remove(self.db_path)
        state_path.unlink()

        with self.assertRaises(TamperDetectedError):
            AuthDatabase(db_path=self.db_path)



if __name__ == "__main__":  # pragma: no cover - convenience
    unittest.main()
