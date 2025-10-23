"""Cross-platform OS integration helpers.

This module consolidates platform-specific affordances required to
ship a polished Secure Vault experience on Windows and macOS alongside
Linux.  It exposes helpers for taskbar/dock interactions, keychain
management, and native dialog access while gracefully degrading when an
integration is unavailable in the current execution environment.
"""
from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from config import default_config

LOGGER = logging.getLogger("secure_vault.platform")


class FileKeychainStorage:
    """File-backed secret storage used when native keyrings are unavailable.

    The storage is scoped to the Secure Vault configuration directory and
    persists secrets in a JSON structure with owner-only permissions.  This
    intentionally mirrors the semantics of desktop keychains so that Windows
    and macOS users benefit from first-class backends while Linux and
    headless environments still retain secure persistence.
    """

    def __init__(self, storage_file: Optional[Path] = None):
        self._path = Path(storage_file) if storage_file else Path(
            default_config.config_dir
        ) / "keychain_fallback.json"
        self._lock = threading.RLock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            self._path.write_text("{}", encoding="utf-8")
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                LOGGER.debug("Unable to set permissions on %s", self._path)
        else:
            try:
                os.chmod(self._path, 0o600)
            except OSError:
                LOGGER.debug("Unable to enforce strict permissions on %s", self._path)

    def _load(self) -> dict:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            LOGGER.warning("Corrupted fallback keychain at %s; resetting", self._path)
            return {}

    def _save(self, data: dict) -> None:
        tmp_path = self._path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data), encoding="utf-8")
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            LOGGER.debug("Unable to tighten permissions on %s", tmp_path)
        tmp_path.replace(self._path)

    def store(self, service: str, account: str, secret: str) -> None:
        with self._lock:
            data = self._load()
            service_bucket = data.setdefault(service, {})
            service_bucket[account] = secret
            self._save(data)

    def get(self, service: str, account: str) -> Optional[str]:
        with self._lock:
            data = self._load()
            return data.get(service, {}).get(account)

    def delete(self, service: str, account: str) -> bool:
        with self._lock:
            data = self._load()
            service_bucket = data.get(service)
            if not service_bucket or account not in service_bucket:
                return False
            del service_bucket[account]
            if not service_bucket:
                data.pop(service, None)
            self._save(data)
            return True


class KeychainAdapter:
    """Facade over the platform keychain with secure fallbacks."""

    def __init__(
        self,
        service_name: str,
        *,
        prefer_fallback: bool = False,
        storage_path: Optional[Path] = None,
    ) -> None:
        self.service_name = service_name
        self._prefer_fallback = prefer_fallback
        self._fallback = FileKeychainStorage(storage_path)
        self._keyring = None
        if not prefer_fallback:
            try:
                import keyring

                # Probe backend early to surface configuration issues.
                keyring.get_keyring()
                self._keyring = keyring
            except Exception as exc:  # pragma: no cover - depends on platform
                LOGGER.warning("Keyring backend unavailable, using fallback: %s", exc)
                self._keyring = None

    def _normalize_secret(self, secret: str | bytes) -> str:
        if isinstance(secret, bytes):
            return secret.decode("utf-8")
        return secret

    def store_secret(self, account: str, secret: str | bytes) -> None:
        normalized = self._normalize_secret(secret)
        if self._keyring is not None:
            try:
                self._keyring.set_password(self.service_name, account, normalized)
                return
            except Exception as exc:  # pragma: no cover - depends on platform
                LOGGER.warning("Keyring storage failed, falling back: %s", exc)
        self._fallback.store(self.service_name, account, normalized)

    def retrieve_secret(self, account: str) -> Optional[str]:
        if self._prefer_fallback:
            return self._fallback.get(self.service_name, account)
        if self._keyring is not None:
            try:
                secret = self._keyring.get_password(self.service_name, account)
                if secret is not None:
                    return secret
            except Exception as exc:  # pragma: no cover - depends on platform
                LOGGER.warning("Keyring retrieval failed, using fallback: %s", exc)
        return self._fallback.get(self.service_name, account)

    def delete_secret(self, account: str) -> bool:
        deleted = False
        if self._keyring is not None and not self._prefer_fallback:
            try:
                self._keyring.delete_password(self.service_name, account)
                deleted = True
            except Exception:  # pragma: no cover - depends on platform
                deleted = False
        return self._fallback.delete(self.service_name, account) or deleted


class BaseTaskbarIntegration:
    """Common interface for interacting with the OS taskbar/dock."""

    def __init__(self, app_name: str) -> None:
        self.app_name = app_name
        self.is_supported = False

    def register(self) -> None:
        """Perform startup registration if the platform supports it."""

    def update_progress(self, value: int, total: int) -> bool:
        """Update a determinate progress indicator when available."""
        return False

    def request_attention(self) -> bool:
        """Ask the OS to draw the user's attention to the application."""
        return False

    def show_notification(self, title: str, message: str) -> bool:
        """Surface an informational notification through native channels."""
        LOGGER.info("%s: %s", title, message)
        return False


class WindowsTaskbarIntegration(BaseTaskbarIntegration):
    """Windows-specific taskbar integration using Win32 APIs."""

    def __init__(self, app_name: str) -> None:
        super().__init__(app_name)
        self._app_id = f"{app_name}.SecureVault"
        self._last_progress: Optional[Tuple[int, int]] = None
        self.register()

    def register(self) -> None:  # pragma: no cover - requires Windows
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                self._app_id
            )
            self.is_supported = True
        except Exception as exc:
            LOGGER.debug("Windows AppUserModelID registration failed: %s", exc)

    def update_progress(self, value: int, total: int) -> bool:
        if total <= 0:
            return False
        self._last_progress = (value, total)
        # The full ITaskbarList3 API requires COM setup; defer to future work.
        return True

    def request_attention(self) -> bool:  # pragma: no cover - requires Windows
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            hwnd = user32.GetConsoleWindow()
            if not hwnd:
                return False

            class FLASHWINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.UINT),
                    ("hwnd", wintypes.HWND),
                    ("dwFlags", wintypes.DWORD),
                    ("uCount", wintypes.UINT),
                    ("dwTimeout", wintypes.DWORD),
                ]

            flash_info = FLASHWINFO()
            flash_info.cbSize = ctypes.sizeof(FLASHWINFO)
            flash_info.hwnd = hwnd
            flash_info.dwFlags = 0x00000003  # FLASHW_ALL
            flash_info.uCount = 3
            flash_info.dwTimeout = 0
            result = bool(user32.FlashWindowEx(ctypes.byref(flash_info)))
            self.is_supported = self.is_supported or result
            return result
        except Exception as exc:
            LOGGER.debug("FlashWindowEx unavailable: %s", exc)
            return False

    def show_notification(self, title: str, message: str) -> bool:  # pragma: no cover
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(0, message, title, 0x00000040)
            return True
        except Exception as exc:
            LOGGER.debug("Windows notification failed: %s", exc)
            return False


class MacOSTaskbarIntegration(BaseTaskbarIntegration):
    """macOS dock integration implemented via AppleScript commands."""

    def register(self) -> None:  # pragma: no cover - depends on macOS
        self.is_supported = shutil.which("osascript") is not None

    def request_attention(self) -> bool:  # pragma: no cover - depends on macOS
        if shutil.which("osascript") is None:
            return False
        script = (
            "tell application \"System Events\" to bounce application \""
            f"{self.app_name}\""
        )
        try:
            subprocess.run(["osascript", "-e", script], check=False)
            return True
        except Exception as exc:
            LOGGER.debug("Dock bounce failed: %s", exc)
            return False

    def show_notification(self, title: str, message: str) -> bool:  # pragma: no cover
        if shutil.which("osascript") is None:
            return False
        script = (
            "display notification \"{message}\" with title \"{title}\"".format(
                title=title.replace("\"", "'"),
                message=message.replace("\"", "'"),
            )
        )
        try:
            subprocess.run(["osascript", "-e", script], check=False)
            return True
        except Exception as exc:
            LOGGER.debug("macOS notification failed: %s", exc)
            return False


class LinuxTaskbarIntegration(BaseTaskbarIntegration):
    """Linux desktop integration relying on freedesktop helpers when present."""

    def __init__(self, app_name: str) -> None:
        super().__init__(app_name)
        self.is_supported = shutil.which("notify-send") is not None

    def show_notification(self, title: str, message: str) -> bool:
        if shutil.which("notify-send") is None:
            return super().show_notification(title, message)
        try:
            subprocess.run(
                ["notify-send", f"{self.app_name}: {title}", message], check=False
            )
            return True
        except Exception as exc:
            LOGGER.debug("notify-send failed: %s", exc)
            return False


@dataclass
class NativeDialogResult:
    """Result object representing a selection returned by native dialogs."""

    path: Optional[Path]
    used_native_dialog: bool


class NativeDialogService:
    """High-level helper for invoking OS-native file and directory dialogs."""

    def __init__(self, app_name: str, *, prefer_cli: bool = False) -> None:
        self.app_name = app_name
        self._prefer_cli = prefer_cli
        self._system = platform.system().lower()

    def _qt_available(self) -> bool:
        if self._prefer_cli:
            return False
        if self._system not in {"windows", "darwin"} and not os.environ.get("DISPLAY"):
            return False
        try:
            from PyQt6.QtWidgets import QApplication  # type: ignore
        except Exception:
            return False
        app = QApplication.instance()
        if app is None:
            try:
                QApplication([])
            except Exception:
                return False
        return True

    def _cli_fallback(self, default: Optional[Path]) -> NativeDialogResult:
        path = default or Path(default_config.config_dir)
        return NativeDialogResult(path=path, used_native_dialog=False)

    def select_directory(self, *, default: Optional[Path] = None) -> NativeDialogResult:
        if not self._qt_available():
            return self._cli_fallback(default)
        from PyQt6.QtWidgets import QApplication, QFileDialog  # type: ignore

        app = QApplication.instance() or QApplication([])
        directory = QFileDialog.getExistingDirectory(
            None, f"{self.app_name} – Select Directory", str(default or Path.home())
        )
        if not directory:
            return NativeDialogResult(path=None, used_native_dialog=True)
        return NativeDialogResult(path=Path(directory), used_native_dialog=True)

    def select_file(self, *, default: Optional[Path] = None) -> NativeDialogResult:
        if not self._qt_available():
            return self._cli_fallback(default)
        from PyQt6.QtWidgets import QApplication, QFileDialog  # type: ignore

        app = QApplication.instance() or QApplication([])
        filename, _ = QFileDialog.getOpenFileName(
            None, f"{self.app_name} – Select File", str(default or Path.home())
        )
        if not filename:
            return NativeDialogResult(path=None, used_native_dialog=True)
        return NativeDialogResult(path=Path(filename), used_native_dialog=True)

    def select_save_file(self, *, default: Optional[Path] = None) -> NativeDialogResult:
        if not self._qt_available():
            return self._cli_fallback(default)
        from PyQt6.QtWidgets import QApplication, QFileDialog  # type: ignore

        app = QApplication.instance() or QApplication([])
        filename, _ = QFileDialog.getSaveFileName(
            None, f"{self.app_name} – Save File", str(default or Path.home())
        )
        if not filename:
            return NativeDialogResult(path=None, used_native_dialog=True)
        return NativeDialogResult(path=Path(filename), used_native_dialog=True)


class PlatformIntegrationManager:
    """Coordinates platform-specific integrations for the application."""

    def __init__(
        self,
        app_name: str = "SecureVault",
        *,
        prefer_cli_dialogs: bool = False,
        keychain_prefer_fallback: bool = False,
        keychain_storage_path: Optional[Path] = None,
    ) -> None:
        self.app_name = app_name
        self._system = platform.system().lower()
        self.taskbar = self._create_taskbar()
        self.keychain = KeychainAdapter(
            app_name,
            prefer_fallback=keychain_prefer_fallback,
            storage_path=keychain_storage_path,
        )
        self.dialogs = NativeDialogService(app_name, prefer_cli=prefer_cli_dialogs)

    def _create_taskbar(self) -> BaseTaskbarIntegration:
        if self._system == "windows":
            return WindowsTaskbarIntegration(self.app_name)
        if self._system == "darwin":
            return MacOSTaskbarIntegration(self.app_name)
        return LinuxTaskbarIntegration(self.app_name)

    def announce_startup(self) -> None:
        """Send a best-effort notification that the application is ready."""
        title = f"{self.app_name} Ready"
        message = "Secure Vault background services are now active."
        if not self.taskbar.show_notification(title, message):
            LOGGER.info("Startup notification displayed via logging channel")

    @property
    def system(self) -> str:
        return self._system


__all__ = [
    "FileKeychainStorage",
    "KeychainAdapter",
    "BaseTaskbarIntegration",
    "WindowsTaskbarIntegration",
    "MacOSTaskbarIntegration",
    "LinuxTaskbarIntegration",
    "NativeDialogResult",
    "NativeDialogService",
    "PlatformIntegrationManager",
]
