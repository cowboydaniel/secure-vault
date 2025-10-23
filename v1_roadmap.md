# Secure Vault v1 Linux Release Roadmap

This roadmap distills the remaining work required to confidently ship the Secure Vault v1 release on Linux. It synthesizes the launch track, defect triage, and operational readiness items that remain open across the codebase and associated process documents.

## 1. Product & Feature Completeness

### 1.1 Access & Authentication Experience
- [ ] Deliver an accessible login flow with a keyboard- and screen-reader-friendly PIN pad.
- [ ] Implement recovery safeguards (multi-step reset confirmation, verified notifications, and secure recovery data handling).
- [ ] Harden secure token storage for CLI workflows with encrypted persistence and automatic rotation.
- [ ] Maintain protected temporary session storage that survives application restarts without weakening guarantees.
- [ ] Add automatic clipboard clearing with configurable dwell times after sensitive copies.
- [ ] Provide inactivity lock functionality rather than relying solely on session expiry.
- [ ] Offer multiple MFA methods: TOTP, hardware security keys (WebAuthn/FIDO2), and biometric unlock where supported.
- [ ] Support secure account sharing and delegation flows for families and teams.
- [ ] Enable encrypted, user-controlled cloud backups of vault state.
- [ ] Issue printable emergency access codes for disaster recovery scenarios.
- [ ] Expand GUI regression automation to cover core authentication, recovery, and sharing flows.

### 1.2 Security & Resilience Core
#### Entropy & Randomness
- [ ] Broaden entropy sources (interrupt, network, disk, and user input timing).
- [ ] Extend statistical randomness analysis and benchmarking coverage.
- [ ] Document usage patterns and publish throughput/quality benchmarks per platform.
- [ ] Provide automatic failover when entropy sources degrade.
- [ ] Support hardware RNG instructions (RDRAND, RDSEED) in a portable manner.
- [ ] Improve entropy mixing and extraction algorithms.

#### Cryptography & Key Management
- [ ] Finish ML-KEM hybrid integration and performance optimization work.
- [ ] Design and implement multi-party workflows (threshold signatures, distributed key generation).
- [ ] Document formal key ceremonies for high-security deployments.
- [ ] Add additional PQC options beyond ML-KEM.

#### Performance & Parallelism
- [ ] Eliminate pipeline bottlenecks through safe parallelization.
- [ ] Reduce memory consumption for large file operations.
- [ ] Add hooks for CPU (e.g., AES-NI) and GPU acceleration.

### 1.3 Platform Footprint
- [ ] Close remaining gaps with Windows/macOS parity per the platform roadmap (taskbar integration, keychain usage, native dialogs, etc.) to ensure cross-platform consistency during v1 support.

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
