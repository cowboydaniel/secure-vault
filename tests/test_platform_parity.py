from __future__ import annotations

from pathlib import Path
from typing import Type

import platform_parity
from platform_parity import (
    FileKeychainStorage,
    KeychainAdapter,
    LinuxTaskbarIntegration,
    MacOSTaskbarIntegration,
    NativeDialogService,
    PlatformIntegrationManager,
    WindowsTaskbarIntegration,
)


def test_file_keychain_storage_roundtrip(tmp_path: Path) -> None:
    storage = FileKeychainStorage(tmp_path / "fallback.json")
    storage.store("svc", "acct", "secret")
    assert storage.get("svc", "acct") == "secret"
    assert storage.delete("svc", "acct")
    assert storage.get("svc", "acct") is None


def test_keychain_adapter_forces_fallback(tmp_path: Path) -> None:
    adapter = KeychainAdapter(
        "TestService",
        prefer_fallback=True,
        storage_path=tmp_path / "keychain.json",
    )
    adapter.store_secret("user", "token")
    assert adapter.retrieve_secret("user") == "token"
    assert adapter.delete_secret("user")


def _manager_for_system(
    monkeypatch,
    tmp_path: Path,
    system_name: str,
    expected_cls: Type,
) -> None:
    monkeypatch.setattr(platform_parity.platform, "system", lambda: system_name)
    manager = PlatformIntegrationManager(
        app_name="TestVault",
        prefer_cli_dialogs=True,
        keychain_prefer_fallback=True,
        keychain_storage_path=tmp_path / f"{system_name.lower()}_keychain.json",
    )
    assert isinstance(manager.taskbar, expected_cls)
    assert manager.system == system_name.lower()


def test_platform_integration_manager_selects_windows(monkeypatch, tmp_path: Path) -> None:
    _manager_for_system(monkeypatch, tmp_path, "Windows", WindowsTaskbarIntegration)


def test_platform_integration_manager_selects_macos(monkeypatch, tmp_path: Path) -> None:
    _manager_for_system(monkeypatch, tmp_path, "Darwin", MacOSTaskbarIntegration)


def test_platform_integration_manager_selects_linux(monkeypatch, tmp_path: Path) -> None:
    _manager_for_system(monkeypatch, tmp_path, "Linux", LinuxTaskbarIntegration)


def test_native_dialog_cli_fallback(tmp_path: Path) -> None:
    service = NativeDialogService("TestVault", prefer_cli=True)
    result = service.select_file(default=tmp_path / "example.txt")
    assert result.path == tmp_path / "example.txt"
    assert not result.used_native_dialog
