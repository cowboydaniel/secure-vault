"""File utility helpers for Secure Vault."""

from __future__ import annotations

import os
from typing import Optional


DEFAULT_MAX_INPUT_SIZE_BYTES = 512 * 1024 * 1024  # 512 MB


class InputFileValidationError(ValueError):
    """Raised when an input file fails validation checks."""


def validate_input_file(
    file_path: str,
    max_size_bytes: Optional[int] = DEFAULT_MAX_INPUT_SIZE_BYTES,
    *,
    allow_empty: bool = False,
) -> int:
    """Validate that ``file_path`` points to a supported input file.

    Args:
        file_path: Path to the file on disk.
        max_size_bytes: Optional maximum allowed size in bytes. ``None`` disables
            the size check.
        allow_empty: Whether empty files are considered valid.

    Returns:
        The size of the validated file in bytes.

    Raises:
        FileNotFoundError: If the path does not exist.
        InputFileValidationError: If the path is not a regular file, is empty
            (when ``allow_empty`` is ``False``), or exceeds ``max_size_bytes``.
    """

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    if not os.path.isfile(file_path):
        raise InputFileValidationError(
            f"Input path '{file_path}' is not a regular file"
        )

    try:
        file_size = os.path.getsize(file_path)
    except OSError as exc:  # pragma: no cover - defensive guard
        raise InputFileValidationError(
            f"Unable to access '{file_path}': {exc}"
        ) from exc

    if file_size == 0 and not allow_empty:
        raise InputFileValidationError(
            f"Input file '{file_path}' is empty and cannot be processed"
        )

    if max_size_bytes is not None and file_size > max_size_bytes:
        raise InputFileValidationError(
            "Input file '{path}' is {size:,} bytes which exceeds the maximum "
            "allowed size of {limit:,} bytes".format(
                path=file_path, size=file_size, limit=max_size_bytes
            )
        )

    return file_size
