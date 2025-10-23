"""Integration tests for secure storage file handling."""

import os
import stat

import pytest

from storage_layer import SecureStorageEngine, StorageFormat


@pytest.fixture
def storage_engine(tmp_path):
    """Provide a storage engine isolated to a temporary directory."""
    return SecureStorageEngine(storage_dir=str(tmp_path))


def _base_metadata():
    return {
        "encryption_layers": ["test"],
        "classification_level": 1,
        "created_by": "pytest",
    }


def test_encrypted_container_permissions(storage_engine):
    """Ensure encrypted container files are written with mode 0o600."""
    metadata = _base_metadata()
    container = storage_engine.store_encrypted_data(
        "file_mode_single",
        b"super secret",
        "secret.bin",
        metadata,
        storage_format=StorageFormat.ENCRYPTED_CONTAINER,
    )

    stored_path = container.metadata.storage_paths[0]
    mode = stat.S_IMODE(os.stat(stored_path, follow_symlinks=False).st_mode)
    assert mode == 0o600


def test_distributed_share_permissions(storage_engine):
    """Ensure distributed share fragments respect restrictive permissions."""
    metadata = _base_metadata()
    container = storage_engine.store_encrypted_data(
        "file_mode_fragments",
        b"fragmented secret data" * 8,
        "secret.bin",
        metadata,
        storage_format=StorageFormat.DISTRIBUTED_SHARES,
    )

    for path in container.metadata.storage_paths:
        mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
        assert mode == 0o600


def test_overwrite_preserves_permissions(storage_engine):
    """Repeated storage operations should continue enforcing permissions."""
    metadata = _base_metadata()
    storage_engine.store_encrypted_data(
        "file_mode_overwrite",
        b"first version",
        "secret.bin",
        metadata,
        storage_format=StorageFormat.ENCRYPTED_CONTAINER,
    )

    container = storage_engine.store_encrypted_data(
        "file_mode_overwrite",
        b"second version",
        "secret.bin",
        metadata,
        storage_format=StorageFormat.ENCRYPTED_CONTAINER,
    )

    stored_path = container.metadata.storage_paths[0]
    mode = stat.S_IMODE(os.stat(stored_path, follow_symlinks=False).st_mode)
    assert mode == 0o600
