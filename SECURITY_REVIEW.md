# Security Review Findings

## Remediated: Guard-wrapped secrets were recoverable from plaintext guard state
InstanceGuard now seals its secret with AES-GCM under a device-bound key derived from
the host identity and optional deployment hints, and transparently migrates legacy
Base64 state into the encrypted representation. Access to `instance_state.json` alone
no longer reveals the raw secret material used by dependent components.

## Remediated: Audit log key replacement via plaintext blobs
The audit logger rejects unwrapped key and chain payloads entirely and treats missing
materials as tampering when historical artifacts exist. Attackers can no longer drop a
plaintext `.audit_log.key` file to replace the encryption material on the next startup.

## Remediated: Tamper chain reset on missing state file
Deleting `.audit_log.chain` while key material persists now causes the logger to abort
startup with a tamper alert instead of silently reseeding the hash chain from zero.

