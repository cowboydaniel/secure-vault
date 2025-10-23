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
