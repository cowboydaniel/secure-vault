"""Regression tests for secure storage schema configuration"""

import json
from pathlib import Path

import pytest

from storage_layer import SecureStorageEngine, SCHEMA_CONFIG_FILENAME


def _write_schema_config(tmp_dir: Path, config: dict) -> Path:
    config_path = tmp_dir / SCHEMA_CONFIG_FILENAME
    config_path.write_text(json.dumps(config))
    return config_path


def test_invalid_table_identifier_raises_error(tmp_path):
    """Ensure unsupported table identifiers from configuration raise clear errors."""

    _write_schema_config(tmp_path, {
        "tables": {
            "unknown_table": {"name": "unknown_table"}
        }
    })

    with pytest.raises(ValueError, match="Unsupported table identifier 'unknown_table'"):
        SecureStorageEngine(storage_dir=tmp_path)


def test_invalid_column_identifier_raises_error(tmp_path):
    """Ensure unsupported column identifiers from configuration raise clear errors."""

    _write_schema_config(tmp_path, {
        "tables": {
            "file_metadata": {
                "columns": ["file_id", "original_name", "nonexistent_column"]
            }
        }
    })

    with pytest.raises(ValueError, match="Unsupported column identifiers for table 'file_metadata'"):
        SecureStorageEngine(storage_dir=tmp_path)

