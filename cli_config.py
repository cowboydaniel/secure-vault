"""Utility helpers for loading CLI configuration files."""

from __future__ import annotations

import configparser
import json
from pathlib import Path
from typing import Any, Dict, List

try:  # Python 3.11+
    import tomllib  # type: ignore[attr-defined]
except ModuleNotFoundError:  # pragma: no cover - fallback for <3.11
    tomllib = None  # type: ignore[assignment]

from config import apply_configuration_overrides


class CLIConfigurationError(Exception):
    """Raised when a CLI configuration file cannot be processed."""


def _convert_value(value: str) -> Any:
    """Attempt to convert string literals to native Python types."""

    lowered = value.strip().lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    try:
        if lowered.startswith("0x"):
            return int(lowered, 16)
        return int(lowered)
    except ValueError:
        pass
    try:
        return float(lowered)
    except ValueError:
        pass
    return value.strip()


def _load_ini(path: Path) -> Dict[str, Any]:
    parser = configparser.ConfigParser()
    parser.read(path)
    data: Dict[str, Any] = {}
    for section in parser.sections():
        section_data: Dict[str, Any] = {}
        for key, value in parser.items(section):
            section_data[key] = _convert_value(value)
        data[section] = section_data
    return data


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_toml(path: Path) -> Dict[str, Any]:
    if tomllib is None:
        raise CLIConfigurationError(
            "TOML configuration requested but tomllib is unavailable on this interpreter."
        )
    with path.open("rb") as handle:
        return tomllib.load(handle)


LOADERS = {
    ".json": _load_json,
    ".toml": _load_toml,
    ".ini": _load_ini,
    ".cfg": _load_ini,
}


def load_cli_configuration(path: str) -> Dict[str, Any]:
    """Load and parse a CLI configuration file."""

    location = Path(path).expanduser().resolve()
    if not location.exists():
        raise CLIConfigurationError(f"Configuration file not found: {location}")

    loader = LOADERS.get(location.suffix.lower())
    if loader is None:
        raise CLIConfigurationError(
            f"Unsupported configuration format '{location.suffix}'. Use JSON, TOML, or INI."
        )

    try:
        return loader(location)
    except CLIConfigurationError:
        raise
    except Exception as exc:  # pragma: no cover - defensive logging path
        raise CLIConfigurationError(f"Failed to load configuration: {exc}") from exc


def apply_cli_configuration(path: str) -> List[str]:
    """Load overrides from ``path`` and apply them to the global configuration."""

    overrides = load_cli_configuration(path)
    return apply_configuration_overrides(overrides)
