import base64
import json
import os
import threading
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from key_manager import KeyManager, KeyType


class KeyManagerConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_path = os.path.join(self.temp_dir.name, "metadata.json")
        self.keys_dir = os.path.join(self.temp_dir.name, "keys")
        self.master_secret = os.urandom(64)
        self.config = {
            "metadata_file": self.metadata_path,
            "keys_dir": self.keys_dir,
            "backup_enabled": False,
            "backup_schedule": 0,
            "rotation_check_interval": 60,
            "master_secret": self.master_secret,
        }
        self.km = KeyManager(self.config)

    def tearDown(self) -> None:
        self.km.close()
        self.temp_dir.cleanup()

    def test_parallel_encrypt_decrypt_cycles(self) -> None:
        key_id, _ = self.km.generate_key(KeyType.SYMMETRIC, key_size=32)
        messages = [f"message-{i}".encode("utf-8") for i in range(10)]
        thread_count = 4
        iterations = 25
        errors = []
        error_lock = threading.Lock()

        def worker(seed: int) -> None:
            try:
                for i in range(iterations):
                    message = messages[(seed + i) % len(messages)]
                    iv_and_tag, ciphertext = self.km.encrypt_with_key(key_id, message)
                    decrypted = self.km.decrypt_with_key(key_id, ciphertext, iv_and_tag)
                    if decrypted != message:
                        raise AssertionError("Decrypted plaintext did not match original message")
            except Exception as exc:  # pragma: no cover - captured for assertion
                with error_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(thread_count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertFalse(errors, f"Errors encountered during parallel operations: {errors}")

        metadata = self.km.get_key_metadata(key_id)
        self.assertIsNotNone(metadata)
        if metadata is None:
            self.fail("Metadata should not be None after key generation")

        expected_operations = thread_count * iterations * 2  # encrypt + decrypt per iteration
        # The key manager increments usage on direct metadata updates and during usage recording.
        self.assertEqual(metadata.usage_count, expected_operations * 2)
        self.assertGreater(metadata.last_used, 0)

    def test_keys_encrypted_on_disk_and_round_trip(self) -> None:
        key_id, _ = self.km.generate_key(KeyType.SYMMETRIC, key_size=32)
        key_bytes = self.km._hsm.retrieve_key(key_id)
        self.assertIsNotNone(key_bytes)
        if key_bytes is None:
            self.fail("retrieve_key returned None for generated key")

        key_path = Path(self.keys_dir) / f"{key_id}.json"
        with open(key_path, "r", encoding="utf-8") as key_file:
            file_data = json.load(key_file)

        self.assertIsInstance(file_data.get("key_data"), dict)
        self.assertIn("ciphertext", file_data["key_data"])
        serialized = json.dumps(file_data["key_data"])
        self.assertNotIn(key_bytes.hex(), serialized)

        # Simulate fresh session by reloading the key manager
        self.km.close()
        self.km = KeyManager(self.config)
        reloaded = self.km._hsm.retrieve_key(key_id)
        self.assertEqual(reloaded, key_bytes)

        stored_payload = b"stored-key-material"
        self.assertTrue(self.km._hsm.store_key("stored_key", stored_payload))
        stored_path = Path(self.keys_dir) / "stored_key.json"
        with open(stored_path, "r", encoding="utf-8") as stored_file:
            stored_data = json.load(stored_file)

        self.assertIsInstance(stored_data.get("key_data"), dict)
        self.assertNotIn(stored_payload.hex(), json.dumps(stored_data["key_data"]))
        self.assertEqual(self.km._hsm.retrieve_key("stored_key"), stored_payload)


class TestFileBasedHSMSecretWrapping(unittest.TestCase):
    def test_local_master_secret_guard_wrapped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir, \
                mock.patch.dict(os.environ, {"SECURE_VAULT_STATE_DIR": os.path.join(tmpdir, "state")}):
            keys_dir = Path(tmpdir) / "keys"
            metadata_file = Path(tmpdir) / "metadata.json"
            auth_db_path = Path(tmpdir) / "users.db"

            config = {
                "metadata_file": str(metadata_file),
                "keys_dir": str(keys_dir),
                "backup_enabled": False,
                "backup_schedule": 0,
                "rotation_check_interval": 0,
                "auth_db_path": str(auth_db_path),
            }

            key_manager = KeyManager(config)
            try:
                key_id, _ = key_manager.generate_key(KeyType.SYMMETRIC, key_size=32)
                derived_secret = key_manager._hsm._load_or_create_local_secret()
                encoded_secret = base64.b64encode(derived_secret).decode("ascii")

                secret_path = keys_dir / ".file_hsm_master_secret"
                self.assertTrue(secret_path.exists())
                file_contents = secret_path.read_text()
                payload = json.loads(file_contents)

                self.assertEqual(payload.get("version"), 2)
                self.assertIn("ciphertext", payload)
                self.assertNotIn(encoded_secret, file_contents)

                original_key = key_manager._hsm.retrieve_key(key_id)
                self.assertIsNotNone(original_key)
            finally:
                key_manager.close()

            reopened = KeyManager(config)
            try:
                reloaded_key = reopened._hsm.retrieve_key(key_id)
                self.assertEqual(reloaded_key, original_key)
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
