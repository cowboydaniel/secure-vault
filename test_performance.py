import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from auth_database import AuthDatabase
from auth_manager import AuthConfig, AuthManager
from auth_queue import AuthQueue


class AuthQueueStressTests(unittest.TestCase):
    """Stress tests for the semaphore-backed authentication queue."""

    def setUp(self) -> None:
        self._prev_state_dir = os.environ.get("SECURE_VAULT_STATE_DIR")
        self._temp_dir = tempfile.TemporaryDirectory()
        os.environ["SECURE_VAULT_STATE_DIR"] = self._temp_dir.name
        self._prev_wrap_secret = os.environ.get("SECURE_VAULT_GUARD_WRAP_SECRET")
        os.environ["SECURE_VAULT_GUARD_WRAP_SECRET"] = "queue-test-wrap"
        self.addCleanup(self._cleanup_tempdir)

        db_path = os.path.join(self._temp_dir.name, "auth.db")
        self.db = AuthDatabase(db_path=db_path)
        self.addCleanup(self.db.close)

        config = AuthConfig(
            argon_concurrency_limit=2,
            argon_wait_warning_seconds=0.05,
            argon_metrics_log_interval=5,
        )
        self.queue = AuthQueue(
            max_concurrent=config.argon_concurrency_limit,
            wait_warning_threshold=config.argon_wait_warning_seconds,
            metrics_log_interval=config.argon_metrics_log_interval,
        )
        self.manager = AuthManager(db=self.db, config=config, auth_queue=self.queue)

    def _cleanup_tempdir(self) -> None:
        if self._prev_state_dir is None:
            os.environ.pop("SECURE_VAULT_STATE_DIR", None)
        else:
            os.environ["SECURE_VAULT_STATE_DIR"] = self._prev_state_dir
        if self._prev_wrap_secret is None:
            os.environ.pop("SECURE_VAULT_GUARD_WRAP_SECRET", None)
        else:
            os.environ["SECURE_VAULT_GUARD_WRAP_SECRET"] = self._prev_wrap_secret
        self._temp_dir.cleanup()

    def test_concurrent_pin_logins_bounded_by_queue(self) -> None:
        email = "queue-test@example.com"
        password = "ComplexPassword!123"
        pin = "839261"

        user_id = self.manager.user_manager.create_user(
            email=email,
            password=password,
            pin=pin,
        )

        credentials = self.db.get_credentials(user_id)
        baseline_key = self.manager.pin_manager.derive_key_from_pin(
            pin,
            credentials.pin_salt,
            algorithm=credentials.kdf_algorithm,
            metadata=credentials.kdf_metadata,
        )
        baseline_key_bytes = bytes(baseline_key)

        active = 0
        peak_active = 0
        lock = threading.Lock()

        def fake_derive(test_pin: str, salt: bytes, **kwargs):
            nonlocal active, peak_active
            self.assertEqual(test_pin, pin)
            self.assertEqual(salt, credentials.pin_salt)
            with lock:
                active += 1
                peak_active = max(peak_active, active)
                current_active = active
            try:
                time.sleep(0.05)
                if current_active > self.queue.max_concurrent:
                    raise AssertionError(
                        f"Argon2 operations exceeded limit: {current_active} > {self.queue.max_concurrent}"
                    )
                return bytearray(baseline_key_bytes)
            finally:
                with lock:
                    active -= 1

        original_derive = self.manager.pin_manager.derive_key_from_pin
        self.manager.pin_manager.derive_key_from_pin = fake_derive  # type: ignore[assignment]
        self.addCleanup(
            lambda: setattr(self.manager.pin_manager, "derive_key_from_pin", original_derive)
        )

        attempt_count = 6
        with ThreadPoolExecutor(max_workers=attempt_count) as executor:
            futures = [
                executor.submit(self.manager.authenticate_with_pin, email, pin)
                for _ in range(attempt_count)
            ]
            sessions = [future.result() for future in futures]

        for session in sessions:
            self.manager.logout(session.session_id)

        snapshot = self.queue.snapshot()

        self.assertLessEqual(
            peak_active,
            self.queue.max_concurrent,
            msg="Semaphore did not constrain concurrent Argon2 operations",
        )
        self.assertGreaterEqual(snapshot.total_requests, attempt_count)
        self.assertGreater(snapshot.max_queue_depth, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
