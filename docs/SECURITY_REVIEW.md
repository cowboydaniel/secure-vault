# Security Review Status

**Current verdict:** incomplete and not release-ready

This document records the security status of the current source tree. Findings
are considered open until the implementation compiles and its regression tests
pass.

## Critical: the current tree cannot be security-tested

The current checkout does not compile. Syntax errors are present in security-
critical application modules, including `audit_logger.py` and
`auth_manager.py`, as well as in shared file utilities and tests. Consequently,
`pytest -q` stops during collection and no end-to-end security claim can be
validated.

Until compilation and test collection are restored:

- the application must not be used for sensitive or production data;
- the findings below describe source-code intent, not verified runtime
  behavior.

## Remediation present in source, runtime verification blocked

### InstanceGuard no longer writes a plaintext secret

`InstanceGuard` removes the legacy `secret` field before writing state and
stores a versioned `secret_wrapped` AES-GCM payload. Its wrapping key is derived
from available host identifiers plus the optional
`SECURE_VAULT_GUARD_WRAP_SECRET` deployment secret. Legacy Base64 secrets are
intended to be migrated to the wrapped format.

Runtime regression tests have not been completed. Host identifiers are not
equivalent to a high-entropy secret; deployments should provide and protect
`SECURE_VAULT_GUARD_WRAP_SECRET`, and review must assess the behavior when it is
absent.

### Audit material rejects unwrapped payloads by design

`AuditLogger._load_wrapped_payload` is intended to accept only a versioned JSON
payload authenticated with AES-GCM and to reject plaintext audit material. The
source also intends to treat a missing audit key or chain state as tampering
when related history already exists.

The current `AuditLogger._load_encryption_material` and `_load_chain_state`
implementations contain duplicated, malformed statements and do not compile.
Audit-key replacement and silent chain-reset protections therefore remain
unverified.

## Open security and assurance work

### High: restore and test the audit logger

Repair the malformed audit material-loading paths, then add regression tests
that prove all of the following:

- raw legacy key and chain blobs are rejected rather than migrated silently;
- missing key material is detected when audit history exists;
- missing chain state is detected when key material exists;
- modified version, nonce, ciphertext, and authentication tags fail closed;
  and
- interrupted writes do not reset or fork the audit chain.

### High: revalidate secret wrapping and local-attacker assumptions

Verify migration from legacy InstanceGuard state, permissions, key derivation,
device changes, backup/restore behavior, and operation with and without the
deployment secret. Document which local attacker capabilities are in scope.

### High: complete an independent cryptographic review

The repository contains an experimental custom cipher and combines several
cryptographic layers. Passing unit tests alone will not establish that the
composition is secure. Obtain independent review before making production or
"unbreakable" security claims.

### Medium: establish continuous security validation

The current GitHub Actions workflow runs dependency auditing only. Add required
pull-request checks for source compilation, tests, linting, type checking, and
headless GUI tests. Resolve the undeclared SciPy test dependency and record the
exact commit and environment for future validation artifacts.

## Closure criteria

This review can be updated from **incomplete** only after:

1. all Python source files compile;
2. the complete test suite collects and passes in a documented environment;
3. audit and InstanceGuard regression tests cover the abuse cases above;
4. CI enforces the same checks on every pull request; and
5. an independent reviewer assesses the cryptographic design and residual
   risks.
