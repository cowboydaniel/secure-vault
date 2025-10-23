"""Tests for secure metadata search functionality."""

import os
import time

import pytest

from metadata_manager import MetadataManager, FileMetadata


def _create_manager(tmp_path):
    db_path = tmp_path / "metadata.db"
    state_dir = tmp_path / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    os.environ["SECURE_VAULT_STATE_DIR"] = str(state_dir)
    os.environ["SECURE_VAULT_GUARD_WRAP_SECRET"] = "metadata-test-wrap"
    return MetadataManager(db_path=str(db_path))


def _sample_metadata(file_id: str, name: str, key_id: str = "key-1") -> FileMetadata:
    return FileMetadata(
        file_id=file_id,
        original_name=name,
        original_size=1234,
        encrypted_size=2048,
        encryption_timestamp=time.time(),
        encryption_algorithm="AES-256-GCM",
        key_id=key_id,
        iv=os.urandom(12),
        integrity_hash="deadbeef",
        compression_used=False,
        tags=["secure", "test"],
        custom_metadata={"purpose": "unit-test"}
    )


def test_search_metadata_blocks_sql_injection(tmp_path):
    manager = _create_manager(tmp_path)

    safe_entries = [
        _sample_metadata("file-1", "report.pdf"),
        _sample_metadata("file-2", "summary.docx"),
    ]

    for entry in safe_entries:
        assert manager.add_file_metadata(entry)

    malicious_input = {"original_name": "x' OR '1'='1' --"}

    results = manager.search_metadata(malicious_input)

    assert results == []


def test_search_metadata_rejects_invalid_sorting(tmp_path):
    manager = _create_manager(tmp_path)

    manager.add_file_metadata(_sample_metadata("file-1", "alpha.txt"))

    with pytest.raises(ValueError):
        manager.search_metadata(sort_by="; DROP TABLE file_metadata;")

    with pytest.raises(ValueError):
        manager.search_metadata(sort_direction="SIDEWAYS")


def test_search_metadata_pagination_limits(tmp_path):
    manager = _create_manager(tmp_path)

    for index in range(5):
        manager.add_file_metadata(_sample_metadata(f"file-{index}", f"item-{index}.bin"))

    # Large limit should be clamped to the maximum
    results = manager.search_metadata(limit=10, offset=0)
    assert len(results) == 5

    # Negative inputs should be rejected
    with pytest.raises(ValueError):
        manager.search_metadata(limit=0)

    with pytest.raises(ValueError):
        manager.search_metadata(offset=-1)

    # Non-integer inputs should raise errors
    with pytest.raises(ValueError):
        manager.search_metadata(limit="100; DROP")

    with pytest.raises(ValueError):
        manager.search_metadata(offset="1 UNION SELECT")
