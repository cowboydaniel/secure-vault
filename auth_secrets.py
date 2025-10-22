"""Utilities for managing authentication secrets stored outside the database."""

from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Dict

CONFIG_DIR = Path(os.path.expanduser("~/.secure_vault"))
CONFIG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

_SECRET_SPECS: Dict[str, int] = {
    "email_pepper": 32,
    "session_pepper": 32,
}

_ENV_PREFIX = "SECURE_VAULT_"


def _secret_path(name: str) -> Path:
    return CONFIG_DIR / f"{name}.key"


def _load_secret_from_env(name: str) -> bytes | None:
    env_key = f"{_ENV_PREFIX}{name.upper()}"
    value = os.getenv(env_key)
    if not value:
        return None
    try:
        return base64.b64decode(value)
    except Exception:
        return value.encode("utf-8")


def _load_or_create_secret(name: str) -> bytes:
    if name not in _SECRET_SPECS:
        raise KeyError(name)

    env_secret = _load_secret_from_env(name)
    if env_secret:
        return env_secret

    path = _secret_path(name)
    if path.exists():
        data = path.read_bytes()
        if len(data) == _SECRET_SPECS[name]:
            return data
    secret = os.urandom(_SECRET_SPECS[name])
    path.write_bytes(secret)
    os.chmod(path, 0o600)
    return secret


def get_email_pepper() -> bytes:
    return _load_or_create_secret("email_pepper")


def get_session_pepper() -> bytes:
    return _load_or_create_secret("session_pepper")
