"""Filesystem safety utilities."""

from __future__ import annotations

import errno
import os
from os import PathLike
from typing import IO, Optional, Union


class SymlinkOpenError(OSError):
    """Error raised when attempting to open a symbolic link."""


_MODE_FLAG_MAP = {
    "r": os.O_RDONLY,
    "r+": os.O_RDWR,
    "w": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
    "w+": os.O_RDWR | os.O_CREAT | os.O_TRUNC,
    "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
    "a+": os.O_RDWR | os.O_CREAT | os.O_APPEND,
    "x": os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    "x+": os.O_RDWR | os.O_CREAT | os.O_EXCL,
}


def _normalize_mode(mode: str) -> str:
    """Normalize an ``open`` mode string by stripping text/binary markers."""

    if not mode:
        raise ValueError("mode string must not be empty")

    valid_chars = set("rwaxtb+")
    if any(ch not in valid_chars for ch in mode):
        raise ValueError(f"invalid mode: {mode!r}")

    normalized = mode.replace("b", "").replace("t", "")

    # Collapse redundant markers (e.g. "rb+" -> "r+")
    if "r" in normalized and "+" in normalized:
        normalized = "r+"
    elif "w" in normalized and "+" in normalized:
        normalized = "w+"
    elif "a" in normalized and "+" in normalized:
        normalized = "a+"
    elif "x" in normalized and "+" in normalized:
        normalized = "x+"

    if normalized not in _MODE_FLAG_MAP:
        raise ValueError(f"unsupported mode: {mode!r}")

    return normalized


def safe_file_open(
    path: Union[str, PathLike[str]],
    mode: str = "r",
    buffering: int = -1,
    encoding: Optional[str] = None,
    errors: Optional[str] = None,
    newline: Optional[str] = None,
) -> IO[Union[str, bytes]]:
    """Secure wrapper around :func:`os.open` that rejects symbolic links.

    The helper mirrors :func:`open` but guarantees that symbolic links are not
    followed by combining an ``os.open`` call with the ``O_NOFOLLOW`` flag.
    """

    flags = os.O_NOFOLLOW | _MODE_FLAG_MAP[_normalize_mode(mode)]
    path_str = os.fspath(path)

    # ``os.open`` with ``O_NOFOLLOW`` raises ``ELOOP`` on symbolic links. We
    # transform that into a clearer exception type for callers.
    try:
        fd = os.open(path_str, flags, 0o600)
    except OSError as exc:  # pragma: no cover - defensive conversion
        if exc.errno == errno.ELOOP:
            raise SymlinkOpenError(exc.errno, f"Refusing to open symbolic link: {path_str}") from exc
        raise

    try:
        return os.fdopen(fd, mode, buffering, encoding, errors, newline)
    except Exception:
        os.close(fd)
        raise

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
"""Utility helpers for secure file system interactions."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Union

from config import StorageConfig

PathLike = Union[str, os.PathLike]


def _normalize_allowlist(paths: Sequence[PathLike]) -> List[Path]:
    """Return normalized, absolute allowlist entries."""
    normalized: List[Path] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        if path not in normalized:
            normalized.append(path)
    return normalized


def _load_allowlist(allowlist: Optional[Iterable[PathLike]]) -> List[Path]:
    """Load and normalize allowlist entries."""
    if allowlist is not None:
        return _normalize_allowlist(list(allowlist))

    configured_paths = StorageConfig.get_allowlisted_directories()
    return _normalize_allowlist(configured_paths)


def _normalize_candidate_path(
    candidate: Optional[PathLike],
    allowlist: Sequence[Path],
) -> Path:
    """Normalize the candidate path relative to the allowlist."""
    if not allowlist:
        raise ValueError("No allowlisted storage directories are configured.")

    if candidate is None or (isinstance(candidate, str) and not candidate.strip()):
        return allowlist[0]

    raw_path = Path(candidate).expanduser()

    if not raw_path.is_absolute():
        raw_path = allowlist[0] / raw_path

    return raw_path.resolve()


def _is_within_allowlist(path: Path, allowlist: Sequence[Path]) -> bool:
    """Return True if ``path`` is located inside any allowlisted directory."""

    for base in allowlist:
        try:
            path.relative_to(base)
            return True
        except ValueError:
            if path == base:
                return True
    return False


def validate_storage_path(
    candidate: Optional[PathLike],
    allowlist: Optional[Iterable[PathLike]] = None,
    *,
    create: bool = False,
    require_directory: bool = True,
) -> Path:
    """Validate that the provided path resides within the configured allowlist.

    Args:
        candidate: Path provided by the caller. ``None`` selects the default
            storage directory from the configuration allowlist.
        allowlist: Optional iterable of additional base directories that will be
            merged with the configured allowlist for validation.
        create: Whether to create the directory hierarchy if it does not exist.
        require_directory: When ``True`` the resulting path must either exist as
            a directory or be creatable as one.

    Returns:
        A resolved :class:`~pathlib.Path` pointing to a safe storage location.

    Raises:
        ValueError: If the path falls outside the allowlisted directories or if
            directory creation was requested and failed.
    """

    normalized_allowlist = _load_allowlist(allowlist)
    candidate_path = _normalize_candidate_path(candidate, normalized_allowlist)

    if not _is_within_allowlist(candidate_path, normalized_allowlist):
        raise ValueError(
            f"Storage path '{candidate_path}' is outside the allowed directories."
        )

    if create:
        try:
            candidate_path.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise ValueError(f"Unable to create storage directory: {exc}") from exc

    if require_directory and candidate_path.exists() and not candidate_path.is_dir():
        raise ValueError(
            f"Storage path '{candidate_path}' exists but is not a directory."
        )

    return candidate_path

__all__ = ["validate_storage_path"]
