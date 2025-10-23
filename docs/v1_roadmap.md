# Secure Vault v1 Linux Release Roadmap

This roadmap distills the remaining work required to confidently ship the Secure Vault v1 release on Linux. It synthesizes the launch track, defect triage, and operational readiness items that remain open across the codebase and associated process documents.

## 1. Product & Feature Completeness

### 1.1 Access & Authentication Experience
- [x] Deliver an accessible login flow with a keyboard- and screen-reader-friendly PIN pad.
- [x] Implement recovery safeguards (multi-step reset confirmation, verified notifications, and secure recovery data handling).
- [x] Harden secure token storage for CLI workflows with encrypted persistence and automatic rotation.
- [x] Maintain protected temporary session storage that survives application restarts without weakening guarantees.
- [x] Add automatic clipboard clearing with configurable dwell times after sensitive copies.
- [x] Provide inactivity lock functionality rather than relying solely on session expiry.
- [x] Offer multiple MFA methods: TOTP, hardware security keys (WebAuthn/FIDO2), and biometric unlock where supported.
- [x] Support secure account sharing and delegation flows for families and teams.
- [x] Enable encrypted, user-controlled cloud backups of vault state.
- [x] Issue printable emergency access codes for disaster recovery scenarios.
- [x] Expand GUI regression automation to cover core authentication, recovery, and sharing flows.

_Status:_ Completed via the accessible PIN pad widget integration (`LINUX_GUI/widgets/accessible_pin_pad.py`), updated login and recovery dialogs, CLI session persistence and inactivity unlock handling (`cli_auth.py`, `cli_session_store.py`), MFA orchestration (`mfa_manager.py`), backend session lock/restore support (`auth_manager.py`), delegation and recovery services (`delegation_manager.py`, `recovery_manager.py`, `cloud_backup.py`, `emergency_codes.py`), and expanded regression coverage validated with `pytest test_security_workflows.py test_gui_regression.py`.

### 1.2 Security & Resilience Core
#### Entropy & Randomness
- [x] Broaden entropy sources (interrupt, network, disk, and user input timing).
- [x] Extend statistical randomness analysis and benchmarking coverage.
- [x] Document usage patterns and publish throughput/quality benchmarks per platform.
- [x] Provide automatic failover when entropy sources degrade.
- [x] Support hardware RNG instructions (RDRAND, RDSEED) in a portable manner.
- [x] Improve entropy mixing and extraction algorithms.

#### Cryptography & Key Management
- [x] Finish ML-KEM hybrid integration and performance optimization work.
- [x] Design and implement multi-party workflows (threshold signatures, distributed key generation).
- [x] Document formal key ceremonies for high-security deployments.
- [x] Add additional PQC options beyond ML-KEM.

#### Performance & Parallelism
- [x] Eliminate pipeline bottlenecks through safe parallelization.
- [x] Reduce memory consumption for large file operations.
- [x] Add hooks for CPU (e.g., AES-NI) and GPU acceleration.

_Status:_ Completed via expanded entropy collectors and benchmarking helpers (`entropy_monitor.py`, `rng_manager.py`, `hardware_rng.py`), hybrid ML-KEM workflows and PQC registry enhancements (`mlkem_layer.py`, `pqc_registry.py`), distributed ceremony orchestration (`distributed_workflows.py`, `threshold_crypto.py`), updated pipeline integration (`pipeline.py`), and supporting documentation in `docs/security_resilience.md` and `docs/key_ceremony.md` with regression coverage (`test_security_resilience_phase12.py`).

### 1.3 Platform Footprint
- [x] Close remaining gaps with Windows/macOS parity per the platform roadmap (taskbar integration, keychain usage, native dialogs, etc.) to ensure cross-platform consistency during v1 support.

_Status:_ Completed via the platform parity service (`platform_parity.py`), CLI keychain integration (`cli_session_store.py`), and startup wiring in `main.py`, providing native taskbar/dock hooks, OS keychain storage, and dialog fallbacks that align Windows and macOS behavior with Linux.

### 1.4 CLI UX & Documentation
- [ ] Provide comprehensive CLI help, configuration file support, progress indicators, and clearer error reporting.
- [ ] Complete user, developer, and API documentation alongside accessibility, localization/i18n, and screen-capture protection guidance.
- [ ] Strengthen UI automation and regression coverage.

## 2. Release-Blocking Defects
The following defects must be addressed before a production cut:
- [x] Fix `SecureMemory.zero` dereferencing `None`.
- [x] Add missing `threading` import in `hardware_rng`.
- [x] Correct wiping behavior in the entropy accumulator.
- [x] Add context-manager support to `secure_alloc`.
- [x] Resolve the syntax error in `auth_database.py`.

## 3. Operational Readiness

### 3.1 Deployment Runbook Compliance
- [ ] Prepare hosts, install dependencies, and execute the full automated test suite.
- [ ] Complete the hardening checklist (systemd integration, secure configuration, and environment validation).
- [ ] Validate end-to-end operation post-deployment and capture verification logs.

### 3.2 Security Release Checklist
- [ ] Ensure all automated tests, static analysis, and dependency scans succeed.
- [ ] Obtain dual-review sign-off for changes.
- [ ] Update docs/changelog/version metadata for v1.
- [ ] Publish security-focused release notes covering cryptographic posture and residual risks.

### 3.3 Artifact Production
- [ ] Run `make release-artifacts` via the release pipeline script once prerequisites are complete.

## 4. Status Tracking
Use this checklist as a living document. Update completion boxes and add links to tickets, PRs, and validation evidence as work progresses towards the Linux v1 release.
