"""Encrypted cloud backup helpers for SecureVault."""

from __future__ import annotations

import json
import logging
import os
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import default_config

logger = logging.getLogger(__name__)


@dataclass
class BackupMetadata:
    created_at: datetime
    source_path: Path
    size_bytes: int
    destination: str


class CloudBackupService:
    """Create encrypted archives suitable for user-controlled cloud storage."""

    def __init__(self, working_dir: Optional[Path] = None) -> None:
        config_dir = Path(default_config.config_dir)
        self._working_dir = working_dir or config_dir / "backups"
        self._working_dir.mkdir(parents=True, exist_ok=True)

    def create_backup(
        self,
        source_paths: Iterable[Path],
        *,
        destination: Path,
        encryption_key: Optional[bytes] = None,
    ) -> BackupMetadata:
        archive_path = self._working_dir / f"vault-{datetime.utcnow().isoformat()}.tar"
        with tarfile.open(archive_path, "w") as archive:
            for path in source_paths:
                archive.add(path, arcname=path.name)

        data = archive_path.read_bytes()
        key = encryption_key or self._derive_key()
        nonce = os.urandom(12)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, data, None)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(nonce + ciphertext)

        metadata = BackupMetadata(
            created_at=datetime.utcnow(),
            source_path=archive_path,
            size_bytes=len(ciphertext),
            destination=str(destination),
        )

        metadata_path = destination.with_suffix(".json")
        metadata_path.write_text(
            json.dumps(
                {
                    "created_at": metadata.created_at.isoformat(),
                    "source": str(archive_path),
                    "size": metadata.size_bytes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return metadata

    def restore_backup(self, backup_file: Path, *, encryption_key: Optional[bytes] = None) -> None:
        blob = backup_file.read_bytes()
        nonce, ciphertext = blob[:12], blob[12:]
        key = encryption_key or self._derive_key()
        aes = AESGCM(key)
        data = aes.decrypt(nonce, ciphertext, None)
        temp_archive = self._working_dir / "restore.tar"
        temp_archive.write_bytes(data)
        with tarfile.open(temp_archive, "r") as archive:
            archive.extractall(path=Path(default_config.config_dir))

    def _derive_key(self) -> bytes:
        key_path = self._working_dir / "cloud_backup.key"
        if key_path.exists():
            data = key_path.read_bytes()
            if len(data) == 32:
                return data
        key = os.urandom(32)
        key_path.write_bytes(key)
        os.chmod(key_path, 0o600)
        return key


__all__ = ["CloudBackupService", "BackupMetadata"]

