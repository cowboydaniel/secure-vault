# Security Review Status

**Current verdict:** incomplete and not release-ready

This document records the security status of the current source tree. Findings
are considered open until the relevant regression tests pass and an independent
cryptographic review is complete.

## Current validation evidence

The [Python CI run for commit `6ae6805`][current-ci] is the current-tree
artifact. Source compilation and test collection proceed, so the former syntax-
error and collection-failure claims are resolved. The configured lint check
(`E9`, `F63`, and `F7`) and the configured type check (`auth_secrets.py` only)
also pass in that run. These narrow checks do not establish repository-wide
lint or type correctness.

The complete pytest job and dedicated headless Qt job are not passing. They do
not substantiate test or GUI completion, and CI has not performed an
independent cryptographic assessment. Until those gaps are closed:

- the application must not be used for sensitive or production data;
- the findings below describe source-code intent, not verified runtime
  behavior.

## Remediation present in source, runtime verification incomplete

### InstanceGuard no longer writes a plaintext secret

`InstanceGuard` removes the legacy `secret` field before writing state and
stores a versioned `secret_wrapped` AES-GCM payload. Its wrapping key is derived
from available host identifiers plus the optional
`SECURE_VAULT_GUARD_WRAP_SECRET` deployment secret. Legacy Base64 secrets are
intended to be migrated to the wrapped format.

The relevant runtime regression suite is not passing. Host identifiers are not
equivalent to a high-entropy secret; deployments should provide and protect
`SECURE_VAULT_GUARD_WRAP_SECRET`, and review must assess the behavior when it is
absent.

### Audit material rejects unwrapped payloads by design

`AuditLogger._load_wrapped_payload` is intended to accept only a versioned JSON
payload authenticated with AES-GCM and to reject plaintext audit material. The
source also intends to treat a missing audit key or chain state as tampering
when related history already exists.

The earlier malformed-statement/compilation finding is resolved by the current
compile job. Audit-key replacement and silent chain-reset protections remain
unverified because the full regression suite does not pass.

## Open security and assurance work

### High: complete audit logger regression validation

Obtain passing regression evidence that proves all of the following:

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

### Medium: complete continuous security validation

The current workflow now runs source compilation, tests, a dedicated headless
GUI subset, fatal-error linting, and a narrow type check on pull requests. Make
the failing jobs green, broaden lint/type coverage, and retain commit-specific
artifacts for release decisions. The separate dependency audit and these
automated checks do not constitute a security review.

## Closure criteria

This review can be updated from **incomplete** only after:

1. all Python source files compile (currently substantiated for `6ae6805` by
   [Python CI][current-ci]);
2. the complete test suite collects and passes in a documented environment;
3. audit and InstanceGuard regression tests cover the abuse cases above;
4. CI enforces the same checks on every pull request; and
5. an independent reviewer assesses the cryptographic design and residual
   risks.

## Historical evidence (not current-tree validation)

The staging transcript dated 2024-06-15 and security-release transcript dated
2024-07-08 describe earlier trees and environments. The 2025-10-23 artifact log
likewise records artifact production, not validation of commit `6ae6805`.
These records remain useful provenance but cannot close a current-tree item.

**Research/non-production warning:** Secure Vault remains an experimental,
educational system. Do not use it to protect sensitive or production data until
the automated blockers are resolved and the cryptographic design and
implementation have completed independent review.

[current-ci]: https://github.com/cowboydaniel/secure-vault/commit/6ae6805c9ba55f1290b7e9fe3b7ee7cc70b130f3/checks
