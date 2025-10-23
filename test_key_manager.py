import os
import threading
import tempfile
import unittest

from key_manager import KeyManager, KeyType


class KeyManagerConcurrencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.metadata_path = os.path.join(self.temp_dir.name, "metadata.json")
        self.keys_dir = os.path.join(self.temp_dir.name, "keys")
        self.config = {
            "metadata_file": self.metadata_path,
            "keys_dir": self.keys_dir,
            "backup_enabled": False,
            "backup_schedule": 0,
            "rotation_check_interval": 60,
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

        expected_usage = thread_count * iterations * 2  # encrypt + decrypt per iteration
        self.assertEqual(metadata.usage_count, expected_usage)
        self.assertGreater(metadata.last_used, 0)


if __name__ == "__main__":
    unittest.main()
