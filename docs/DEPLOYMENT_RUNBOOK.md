# Deployment Runbook

This runbook captures the operational steps for rolling out SecureVault. It is
intended for operators with shell access to the target host. Compliance evidence
for the latest dry-run is archived in
[`DEPLOYMENT_COMPLIANCE_REPORT.md`](DEPLOYMENT_COMPLIANCE_REPORT.md) alongside
`logs/deployment_validation_2024-06-15.log`.

## 1. Preparation

1. Clone or update the repository on the target system.
2. Install dependencies by running `./install_dependencies.sh`.
3. Build the post-quantum libraries with `./build_liboqs.sh`.
4. Execute `./run_tests.sh` (or the relevant subset) to confirm the build passes.
5. Stage configuration files in the service account's home directory.

## 2. Hardening Sign-off

Operators must acknowledge every checkbox before advancing to deployment. The
full rationale for each item is documented in [SECURITY_CONFIG.md](SECURITY_CONFIG.md).

- [ ] File permission baseline applied (InstanceGuard state directory, authentication database, peppers, storage assets). See [Security Configuration Baseline](SECURITY_CONFIG.md#file-permission-baseline).
- [ ] Environment variables injected via an approved secret mechanism (`SECURE_VAULT_STATE_DIR`, `SECURE_VAULT_EMAIL_PEPPER`, `SECURE_VAULT_SESSION_PEPPER`, PKCS#11 variables as applicable).
- [ ] Hardening checklist signed and archived alongside the change ticket. Capture operator and reviewer signatures.

## 3. Deployment

1. Create or update the systemd unit/service wrapper to launch `run_secure_vault.sh`
   as the dedicated service account.
2. Verify the service account `umask` is set to `077`.
3. Start the service and monitor logs for tamper or permission errors.
4. Trigger a test encryption and decryption cycle to validate end-to-end operation.

## 4. Post-Deployment Verification

1. Confirm InstanceGuard status is `provisioned` and no lockdowns occurred.
2. Inspect storage directories to confirm permissions remain enforced.
3. Rotate temporary secrets used during deployment (PINs, PKCS#11 test values).
4. File the signed hardening checklist with the deployment record.
