"""Printable emergency access codes for disaster recovery."""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import List

from auth_secrets import get_session_pepper
from config import default_config


@dataclass
class EmergencyCode:
    code: str
    label: str


class EmergencyCodeManager:
    """Generate and manage emergency one-time access codes."""

    STORE_FILENAME = "emergency_codes.json"

    def __init__(self, store_path: Path | None = None) -> None:
        config_dir = Path(default_config.config_dir)
        self._store_path = store_path or config_dir / self.STORE_FILENAME
        self._codes: List[EmergencyCode] = []
        self._load()

    def generate_codes(self, count: int = 10) -> List[EmergencyCode]:
        pepper = get_session_pepper()
        new_codes: List[EmergencyCode] = []
        for index in range(count):
            random_bytes = secrets.token_bytes(6)
            code = (pepper[index % len(pepper)] ^ random_bytes[0]) % 100
            formatted = f"{code:02d}-{random_bytes.hex().upper()}"
            label = f"Emergency Code {len(self._codes) + index + 1}"
            new_codes.append(EmergencyCode(code=formatted, label=label))

        self._codes = new_codes
        self._persist()
        return list(self._codes)

    def list_codes(self) -> List[EmergencyCode]:
        return list(self._codes)

    def _load(self) -> None:
        if not self._store_path.exists():
            return
        payload = json.loads(self._store_path.read_text(encoding="utf-8"))
        self._codes = [EmergencyCode(**entry) for entry in payload]

    def _persist(self) -> None:
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        data = [code.__dict__ for code in self._codes]
        tmp = self._store_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self._store_path)


__all__ = ["EmergencyCodeManager", "EmergencyCode"]

