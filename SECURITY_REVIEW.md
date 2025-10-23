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
## High: Guard-wrapped secrets remain decryptable due to plaintext instance secret
The new secret-wrapping logic in both the audit logger and file-based HSM now derives
its keys from the InstanceGuard secret. However, the guard still persists its master
secret directly in `instance_state.json`, merely Base64-encoding the value. Anyone who
can read that file can therefore derive the exact wrapping keys and decrypt the
"protected" materials without needing additional secrets. This means the new wrapping
does not meaningfully raise the bar for a local attacker.

Relevant code:
- `instance_guard.py` persists the guard secret as Base64 in the JSON state.  
- `hsm_integration.py` and `audit_logger.py` derive wrap keys directly from that
  plaintext secret.

## High: Audit log key can be replaced with attacker-controlled material
`AuditLogger._load_encryption_material` re-accepts legacy plaintext key blobs by
checking only their length before re-wrapping them with AES-GCM. An attacker who can
write to `.audit_log.key` may therefore drop 128 bytes of chosen key+IV material,
have the service re-wrap it on next startup, and thereafter decrypt or forge every new
audit entry.

## Medium: Tamper chain resets silently if its state file is removed
If `.audit_log.chain` is deleted, `_load_chain_state` simply returns a zero-filled hash
and `_persist_chain_state` immediately writes it back. No tamper alarm is raised, so an
attacker can delete the file while the service is down, modify historical logs, and the
next run will continue from a blank chain without detection.

