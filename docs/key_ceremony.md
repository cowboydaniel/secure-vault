# Formal Key Ceremony Guidance

This guide outlines a repeatable ceremony process for high-assurance
deployments that rely on the `distributed_workflows.MultiPartyKeyWorkflow`
module.

## Prerequisites

* At least `threshold` participants with ML-KEM-1024 public keys.
* Optional: classical X25519 public keys for hybrid encapsulation.
* Access to a hardened coordination host with the Secure Vault codebase.

## Ceremony Stages

1. **Participant Registration**
   ```python
   workflow = MultiPartyKeyWorkflow(threshold=3, total_shares=5)
   workflow.add_participant("alice", alice_mlkem_pub)
   workflow.add_participant("bob", bob_mlkem_pub)
   workflow.add_participant("carol", carol_mlkem_pub)
   workflow.add_participant("dave", dave_mlkem_pub)
   workflow.add_participant("erin", erin_mlkem_pub)
   ```

2. **Secret Generation & Splitting**
   ```python
   secret = secure_random_bytes(64)
   state = workflow.initiate_ceremony(secret)
   ```
   The ceremony state contains Shamir shares and hybrid ML-KEM packages for
   each participant.

3. **Package Distribution**
   * Export participant packages via `workflow.get_participant_package(pid)`.
   * Deliver ciphertext and associated metadata over mutually authenticated
     channels (e.g., hardware token, QR code, or encrypted email).

4. **Acknowledgement Tracking**
   * Once a participant confirms successful import, call
     `workflow.record_acknowledgement(pid)`.
   * Monitor outstanding acknowledgements via the ceremony transcript.

5. **Recovery Procedure**
   ```python
   recovered = workflow.recover_secret(["alice", "bob", "carol"])
   assert recovered == secret
   ```

6. **Audit Trail**
   * Persist the output of `workflow.export_transcript()` to a secured audit
     location alongside hardware RNG health reports and entropy benchmarks.

## Operational Recommendations

* Rotate participant key material annually or after any suspected compromise.
* Store hybrid packages in tamper-evident media with dual control.
* Record entropy benchmark snapshots before and after the ceremony to validate
  RNG health.

