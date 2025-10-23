# Deployment Runbook Compliance Record

This document captures the evidence collected while executing the Secure Vault deployment runbook ahead of the v1 Linux release.
It links the procedural checklist to the validation artifacts operators recorded on the staging environment `sv-lnx-stage-01` on
2024-06-15.

## 1. Host Preparation

- [x] Repository synchronized to `main` and submodules refreshed (`git pull --ff-only`).
- [x] Dependencies installed via `./install_dependencies.sh` with no missing packages or permission errors.
- [x] Post-quantum support libraries compiled through `./build_liboqs.sh` (OpenSSL and liboqs artifacts verified).
- [x] Automated test suites executed using `pytest -q` targeting security, GUI, and CLI coverage.
- [x] Service configuration files staged under `/etc/secure-vault/` with owner-only permissions.

**Command transcript:** See `logs/deployment_validation_2024-06-15.log` lines 1-9 for the captured terminal session confirming the
repository sync, dependency installation, library build, and pytest execution steps.

## 2. Hardening Checklist Sign-off

- [x] InstanceGuard state directory (`/var/lib/secure-vault/state`) confirmed at mode `0700` with root-owned tamper metadata.
- [x] Authentication database (`/var/lib/secure-vault/users.db`) verified at mode `0600` with encrypted backups enabled.
- [x] Secret material directory (`/var/lib/secure-vault/secrets`) enforced at `0700`; peppers injected via environment overrides.
- [x] Storage directories (`containers/`, `fragments/`, `steganography/`, `temp/`, `backup/`) audited for `0700` inheritance and
share artifacts restricted to `0600`.
- [x] Environment variables sourced from Vault-provisioned drop-in at `/etc/secure-vault/env.d/secure.conf`.
- [x] PKCS#11 validation variables scoped to the deployment window and rotated post-checklist.
- [x] Signed checklist archived in ticket `OPS-7421` with operator and reviewer signatures.

Supporting rationale corresponds to `docs/SECURITY_CONFIG.md`; evidence of the permission and environment checks is recorded in
`logs/deployment_validation_2024-06-15.log` lines 10-22.

## 3. Deployment & Verification

- [x] Systemd unit `secure-vault.service` updated to launch `run_secure_vault.sh` under the `securevault` account with `UMask=0077`.
- [x] Service started cleanly; journal inspection confirmed absence of permission or tamper alarms.
- [x] End-to-end encrypt/decrypt smoke test executed via `python -m tests.end_to_end_smoke`.
- [x] Verification logs collected and attached to the deployment record.

**Verification log excerpt:** Refer to `logs/deployment_validation_2024-06-15.log` lines 23-38 showing the systemd status check,
smoke test invocation, and summary of the captured artifacts stored alongside the change record.

## 4. Summary

The staging deployment satisfies all items under _Phase 3.1 Deployment Runbook Compliance_. The referenced log file and ticket
attachments provide the complete evidence trail required for production sign-off.
