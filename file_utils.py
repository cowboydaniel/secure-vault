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

