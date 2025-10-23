# Secure Vault v1 Security Release Notes

## Release Overview
- **Release version:** 1.0.0
- **Release date:** 2024-07-08
- **Target platform:** Linux

Secure Vault v1 for Linux delivers a hardened authentication stack, resilient key
management layers, and operational safeguards required for the initial general
availability launch. The release incorporates broad entropy improvements,
post-quantum readiness, and comprehensive recovery and delegation workflows that
were validated throughout the v1 roadmap effort.

## Validation Summary
- **Automated test suite:** `pytest`
- **Static analysis:** `flake8`, `mypy`
- **Dependency scan:** `pip-audit`
- **Execution context:** CI pipeline run `ci/linux-v1-release/2024-07-08T09:30Z`

Each validation stage completed without failures. The commands were executed on a
clean Linux runner with the full dependency matrix defined in
`requirements.txt` and the hardware-backed entropy collectors enabled.
Artifacts for the run, including HTML reports and raw command logs, are archived
at `logs/security_release_validation_2024-07-08.log`.

## Cryptographic Posture
- Hybrid ML-KEM key exchange flows are enforced by default with automatic
  negotiation for compatible peers via the `mlkem_layer` orchestrator.
- Threshold key ceremonies and distributed signing continue to use the
  multi-party protocol defined in `threshold_crypto.py` and documented in
  `docs/key_ceremony.md`.
- Hardware RNG sources (RDSEED/RDRAND plus external USB entropy) are blended with
  software entropy using the strengthened extractor pipeline described in
  `entropy_monitor.py` and `rng_manager.py`.
- Secure storage and delegation features rely on audited AES-GCM key wrapping and
  Argon2id password derivation parameters calibrated for 2024 hardware.

## Residual Risks & Mitigations
- **Hardware variance:** Systems without RDSEED/RDRAND support rely solely on
  external entropy sources. Operators should confirm
  `vault_health.py --check-entropy` reports healthy pools after deployment.
- **GUI dependencies:** Minimal X11/Wayland stacks are required for the PyQt6
  interface. Headless deployments should use the CLI flows documented in
  `docs/CLI_GUIDE.md`.
- **Post-quantum upgrades:** liboqs-backed algorithms remain optional. Enabling
  them requires compiling liboqs via `build_liboqs.sh` and re-running the
  release validation suite.

## Acknowledgements
Dual-review was completed by **A. Rivera** and **S. Nakamura** on 2024-07-07.
Threat modeling inputs from the security review team (see `docs/SECURITY_REVIEW.md`)
were incorporated into the final checklist and release collateral.
