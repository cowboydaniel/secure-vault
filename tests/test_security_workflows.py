"""Integration tests for security workflows introduced in phase 1.1."""

from __future__ import annotations

import base64
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from access_control import PermissionLevel
from cli_session_store import EncryptedSessionStore, PersistentSession
from cloud_backup import CloudBackupService
from delegation_manager import DelegationManager
from emergency_codes import EmergencyCodeManager
from mfa_manager import MFAManager, MFAResponse
from recovery_manager import RecoveryManager


def _tmp_paths(tmp_path: Path, names: Iterable[str]) -> Iterable[Path]:
    for name in names:
        path = tmp_path / name
        path.write_text(name, encoding="utf-8")
        yield path


def test_mfa_manager_totp(tmp_path: Path) -> None:
    manager = MFAManager(store_path=tmp_path / "mfa_totp.json")
    secret = "JBSWY3DPEHPK3PXP"
    manager.enroll_totp(1, secret)

    challenge = manager.build_challenge(1)
    assert challenge.challenge_type == "totp"
    counter = int(time.time() // challenge.metadata["step"])
    code = MFAManager._generate_totp(secret, counter, challenge.metadata["digits"])
    assert manager.verify_response(1, MFAResponse("totp", {"code": code}))


def test_mfa_manager_hardware(tmp_path: Path) -> None:
    manager = MFAManager(store_path=tmp_path / "mfa_hw.json")
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manager.enroll_hardware_key(1, public_pem)

    challenge = manager.build_challenge(1)
    assert challenge.challenge_type == "hardware_key"
    challenge_bytes = base64.b64decode(challenge.metadata["challenge"])
    signature = private_key.sign(challenge_bytes, ec.ECDSA(hashes.SHA256()))
    assert manager.verify_response(
        1, MFAResponse("hardware_key", {"signature": base64.b64encode(signature).decode("ascii")})
    )


def test_mfa_manager_biometric(tmp_path: Path) -> None:
    manager = MFAManager(store_path=tmp_path / "mfa_bio.json")
    manager.enroll_biometric(1, [0.1, 0.2, 0.3])
    challenge = manager.build_challenge(1)
    assert challenge.challenge_type == "biometric"
    assert manager.verify_response(1, MFAResponse("biometric", {"sample": [0.1, 0.2, 0.3]}))


def test_encrypted_session_store_roundtrip(tmp_path: Path) -> None:
    store = EncryptedSessionStore(
        store_path=tmp_path / "sessions.enc",
        keychain_storage_path=tmp_path / "keychain.json",
        keychain_prefer_fallback=True,
    )
    session = PersistentSession(
        session_id="abc",
        user_id=1,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=1),
        ip_address="127.0.0.1",
        user_agent="test",
        master_key=b"master",
    )
    store.append(session)
    loaded = store.load_sessions()
    assert loaded[0].master_key == b"master"


def test_recovery_manager(tmp_path: Path) -> None:
    manager = RecoveryManager(store_path=tmp_path / "recovery.json")
    code = manager.issue_code("user@example.com")
    assert manager.verify_code("user@example.com", code)


def test_delegation_manager(tmp_path: Path) -> None:
    manager = DelegationManager(store_path=tmp_path / "delegations.json")
    record = manager.create_delegation(
        delegation_id="del-1",
        grantor_id=1,
        grantee_email="friend@example.com",
        permission=PermissionLevel.READ,
        payload=b"shared",  # type: ignore[arg-type]
    )
    payload = manager.retrieve_payload(record.delegation_id)
    assert payload == b"shared"
    manager.revoke(record.delegation_id)
    assert manager.retrieve_payload(record.delegation_id) is None


def test_cloud_backup_service(tmp_path: Path) -> None:
    service = CloudBackupService(working_dir=tmp_path / "work")
    source_files = list(_tmp_paths(tmp_path, ["a.txt", "b.txt"]))
    destination = tmp_path / "backup.enc"
    metadata = service.create_backup(source_files, destination=destination)
    assert destination.exists()
    assert metadata.size_bytes > 0


def test_emergency_codes(tmp_path: Path) -> None:
    manager = EmergencyCodeManager(store_path=tmp_path / "codes.json")
    codes = manager.generate_codes(3)
    assert len(codes) == 3
    assert all("-" in code.code for code in manager.list_codes())
