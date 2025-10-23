"""Centralized error handling utilities for SecureVault."""

from __future__ import annotations

import logging
import re
import traceback
from typing import Optional, Type, TypeVar


_LOGGER = logging.getLogger("secure_vault.error_handler")

_DEFAULT_MESSAGE = "An unexpected error occurred. Please contact support."

_EXCEPTION_TYPE = TypeVar("_EXCEPTION_TYPE", bound=Exception)

_SENSITIVE_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)([\w\-]*?(token|secret|password|key))\s*[:=]\s*(['\"]?)([^'\"\s]+)\3"
)

_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[A-Za-z0-9\._\-]+")

_UNIX_PATH_PATTERN = re.compile(r"(\/[\w\-.]+(?:\/[\w\-.]+)*)")
_WINDOWS_PATH_PATTERN = re.compile(r"([A-Za-z]:\\(?:[\w\-. ]+\\)*[\w\-. ]+)")


class SecureVaultError(Exception):
    """Generic sanitized error surfaced to SecureVault users."""


def _redact_sensitive_tokens(text: str) -> str:
    def _replace_assignment(match: re.Match) -> str:
        category = match.group(2).lower()
        return f"<redacted {category}>"

    redacted = _SENSITIVE_ASSIGNMENT_PATTERN.sub(_replace_assignment, text)
    redacted = _BEARER_PATTERN.sub("Bearer <redacted token>", redacted)
    return redacted


def _redact_paths(text: str) -> str:
    redacted = _UNIX_PATH_PATTERN.sub("<path>", text)
    redacted = _WINDOWS_PATH_PATTERN.sub("<path>", redacted)
    return redacted


def sanitize_text(text: str) -> str:
    """Redact sensitive tokens and filesystem paths from the provided text."""

    if not text:
        return ""

    sanitized = _redact_sensitive_tokens(text)
    sanitized = _redact_paths(sanitized)
    return sanitized


def sanitize_user_message(message: Optional[str]) -> str:
    """Return a sanitized user-facing error message."""

    base_message = message or _DEFAULT_MESSAGE
    sanitized = sanitize_text(base_message)
    # Ensure user messages are single-line to avoid leaking stack traces.
    return sanitized.splitlines()[0].strip()


def sanitize_stack_trace(exc: Exception) -> str:
    """Return a sanitized stack trace for logging."""

    stack = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return sanitize_text(stack)


def log_exception(
    exc: Exception,
    *,
    logger: Optional[logging.Logger] = None,
    context: Optional[str] = None,
) -> None:
    """Log a sanitized stack trace for the provided exception."""

    sanitized_stack = sanitize_stack_trace(exc)
    active_logger = logger or _LOGGER
    prefix = f"{context}: " if context else ""
    active_logger.error("%s%s", prefix, sanitized_stack)


def wrap_exception(
    exc: Exception,
    user_message: Optional[str] = None,
    *,
    error_cls: Type[_EXCEPTION_TYPE] = SecureVaultError,
    logger: Optional[logging.Logger] = None,
    context: Optional[str] = None,
) -> _EXCEPTION_TYPE:
    """Wrap *exc* in a sanitized exception that can be safely surfaced to users."""

    log_exception(exc, logger=logger, context=context)
    sanitized_message = sanitize_user_message(user_message)
    return error_cls(sanitized_message)


def emit_user_message(
    exc: Exception,
    user_message: Optional[str] = None,
    *,
    logger: Optional[logging.Logger] = None,
    context: Optional[str] = None,
) -> str:
    """Log *exc* and return a sanitized user-facing error message."""

    log_exception(exc, logger=logger, context=context)
    return sanitize_user_message(user_message)
