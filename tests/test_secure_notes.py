"""Tests for SecureNotesVault secure key handling."""

from __future__ import annotations

import base64
import json
import stat
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from secure_notes import (
    FALLBACK_ASSOCIATED_DATA,
    FALLBACK_ENVELOPE_VERSION,
    FALLBACK_WRAP_INFO,
    SecureNote,
    SecureNotesLockedError,
    SecureNotesVault,
)


class DummySession:
    """Minimal stand-in for an authenticated session."""

    def __init__(self, master_key: bytes) -> None:
        self._master_key = master_key

    @contextmanager
    def master_key(self) -> Iterator[bytes]:
        yield self._master_key


class SecureNotesVaultTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base_path = Path(self.temp_dir.name)
        self.storage_path = self.base_path / "notes.vault"
        self.key_path = self.base_path / "notes.key"
        self.salt_path = self.base_path / "notes.salt"

        self.master_key = b"m" * 32
        self.device_secret = b"d" * 32

        self.session = DummySession(self.master_key)

    def _build_vault(
        self,
        *,
        session_provider: Optional[DummySession],
        device_secret: Optional[bytes],
    ) -> SecureNotesVault:
        def provide_session() -> Optional[DummySession]:
            return session_provider

        def provide_device_secret() -> Optional[bytes]:
            return device_secret

        vault = SecureNotesVault(
            storage_path=self.storage_path,
            key_fallback_path=self.key_path,
            session_provider=provide_session,
            device_secret_provider=provide_device_secret,
        )
        vault.salt_path = self.salt_path
        return vault

    def test_authenticated_load_uses_session_and_wraps_fallback_key(self) -> None:
        vault = self._build_vault(session_provider=self.session, device_secret=self.device_secret)

        notes = [
            SecureNote(
                note_id="1",
                title="Test",
                body="Secret",
                created_at=time.time(),
                updated_at=time.time(),
            )
        ]
        vault.save_notes(notes)

        self.assertTrue(self.key_path.exists())
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), stat.S_IRUSR | stat.S_IWUSR)

        fallback_payload = json.loads(self.key_path.read_text(encoding="utf-8"))
        self.assertEqual(fallback_payload["version"], FALLBACK_ENVELOPE_VERSION)

        wrap_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.device_secret,
            info=FALLBACK_WRAP_INFO,
        )
        wrap_key = wrap_hkdf.derive(self.master_key)
        aesgcm = AESGCM(wrap_key)
        nonce = base64.b64decode(fallback_payload["nonce"])
        ciphertext = base64.b64decode(fallback_payload["ciphertext"])
        unsealed_key = aesgcm.decrypt(nonce, ciphertext, FALLBACK_ASSOCIATED_DATA)
        self.assertEqual(unsealed_key, vault._cached_key)
        self.assertNotEqual(ciphertext, vault._cached_key)

        fresh_vault = self._build_vault(
            session_provider=self.session,
            device_secret=self.device_secret,
        )
        loaded = fresh_vault.load_notes()
        self.assertEqual([(note.note_id, note.title) for note in loaded], [("1", "Test")])

    def test_unauthenticated_load_requires_reauthentication(self) -> None:
        vault = self._build_vault(session_provider=self.session, device_secret=self.device_secret)
        vault.save_notes([])

        unauthenticated_vault = self._build_vault(
            session_provider=None,
            device_secret=self.device_secret,
        )

        with self.assertRaisesRegex(
            SecureNotesLockedError,
            "re-authenticate",
        ):
            unauthenticated_vault.load_notes()

        self.assertTrue(self.key_path.exists())


if __name__ == "__main__":  # pragma: no cover - unittest main entry point
    unittest.main()
