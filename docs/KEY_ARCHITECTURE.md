# SecureVault Key Architecture

This document clarifies the **separate and independent** key hierarchies used in SecureVault to avoid confusion.

## Two Independent Key Systems

SecureVault uses **two completely separate key systems** that do not interact:

### 1. Authentication Vault Master Key

**Purpose**: Protects internal vault features and metadata

**Used For**:
- Secure Notes encryption (via HKDF derivation)
- Future: Vault metadata, settings, passwords
- Future: Other authentication-gated features

**Key Hierarchy**:
```
User PIN
  └─→ Argon2id KDF (with salt)
      └─→ PIN-Derived Key
          └─→ Encrypts: Vault Master Key (256-bit, stored encrypted in database)
              └─→ HKDF
                  └─→ AES-256-GCM Key
                      └─→ Encrypts: Secure Notes
```

**Storage**:
- `users.db` → `auth_credentials` table → `encrypted_master_key` column
- The vault master key is **never stored in plaintext**
- Decrypted only when user authenticates with PIN
- Lives in session memory while user is logged in

**Affected by PIN Reset**: ✅ YES
- New vault master key generated
- Old secure notes become inaccessible
- User must export notes before PIN reset

---

### 2. File Encryption Keys (5-Layer System)

**Purpose**: Encrypt/decrypt files using the 5-layer pipeline

**Used For**:
- Main file encryption/decryption operations
- All files encrypted via `main.py encrypt` or GUI encrypt

**Key Hierarchy**:
```
Each Encryption Operation (per file):
  ├─→ IDA Layer: Reed-Solomon encoding (no keys, just encoding)
  ├─→ OTP Layer: Fresh random keys per share (os.urandom, one-time use)
  ├─→ ML-KEM Layer: Fresh keypair per operation (post-quantum)
  ├─→ Custom Cipher: Fresh 512-bit master key per operation (secure_random_bytes)
  └─→ Storage Layer: Metadata and file storage
```

**Key Generation** (from `pipeline.py:559`):
```python
# Fresh key generated for EACH encryption operation
master_key = secure_random_bytes(self.cipher_engine.KEY_SIZE)
```

**Storage**:
- Keys are stored **with the encrypted file** (embedded in metadata)
- OTP keys: Generated fresh, used once, securely wiped
- ML-KEM keys: Generated per operation, encapsulated with ciphertext
- Custom cipher key: Generated per operation, encrypted via ML-KEM

**Affected by PIN Reset**: ❌ NO
- File encryption is completely independent
- Keys are generated per-operation, not derived from vault master key
- PIN reset has **zero impact** on encrypted files

---

## Key Differences

| Feature | Authentication Vault Master Key | File Encryption Keys |
|---------|--------------------------------|---------------------|
| **Derived from** | User's PIN via Argon2id | Fresh random per operation |
| **Lifetime** | Persistent (stored encrypted) | Per-file (stored with file) |
| **Scope** | Vault-wide (Secure Notes, metadata) | Single file only |
| **Affected by PIN reset** | ✅ YES - regenerated | ❌ NO - independent |
| **Code location** | `auth_manager.py`, `pin_manager.py` | `pipeline.py`, layer modules |
| **Database storage** | `users.db` (encrypted) | Embedded in `.sec` files |

---

## What Gets Lost on PIN Reset?

### ❌ Lost (Cannot Recover)
- **Secure Notes** - All notes encrypted with the old vault master key
- Any future features that use the vault master key

### ✅ Safe (NOT Affected)
- **All encrypted files** - Files use independent encryption keys
- File metadata and encryption parameters
- Any backups or shares of encrypted files

---

## Common Misconceptions (Now Fixed)

### ❌ WRONG (Old Warning)
> "Resetting your PIN will make all encrypted files inaccessible"

### ✅ CORRECT (New Warning)
> "Resetting your PIN will make Secure Notes inaccessible. Files encrypted through the 5-layer system are NOT affected."

---

## Code References

### Authentication Vault Master Key Usage

**Generation**: `pin_manager.py:158`
```python
def generate_master_key(self) -> bytes:
    return os.urandom(32)  # 256-bit key
```

**Encryption**: `pin_manager.py:261-285`
```python
def encrypt_master_key(self, master_key, pin_derived_key, associated_data):
    # Uses AES-256-GCM
```

**Usage for Secure Notes**: `secure_notes.py:91-110`
```python
master_key = session.get_master_key()
# Derive note encryption key via HKDF
hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"SecureNotesVault")
key = hkdf.derive(master_key)
```

### File Encryption Keys

**Generation**: `pipeline.py:559`
```python
master_key = secure_random_bytes(self.cipher_engine.KEY_SIZE)
cipher_context = self.cipher_engine.create_context(master_key)
```

**OTP Keys**: `otp_layer.py`
```python
# Fresh key per share
otp_key = secure_random_bytes(share_size)
```

**ML-KEM Keys**: `mlkem_layer.py`
```python
# Fresh keypair per operation
keypair = self.mlkem.keygen()
```

---

## Design Rationale

### Why Two Separate Systems?

1. **Security Isolation**
   - Authentication compromise doesn't affect file encryption
   - File encryption compromise doesn't affect vault access

2. **Perfect Forward Secrecy (Files)**
   - Each file uses unique, independent keys
   - Compromise of one file doesn't affect others
   - Old encrypted files remain secure even if current keys compromised

3. **Convenience (Vault Features)**
   - Secure Notes available immediately after login
   - No need to remember file-specific passwords
   - Vault-wide features use single key hierarchy

4. **Future Flexibility**
   - Can add password-based vault master key recovery without affecting file security
   - Can change authentication method without re-encrypting files
   - Can add new vault features easily

---

## For Developers

### Adding New Vault Features

If you're adding a feature that needs encryption:

**Use Vault Master Key if**:
- Feature is vault-wide (like Secure Notes)
- User should access it immediately after login
- Lost on PIN reset is acceptable

**Use Independent Keys if**:
- Feature encrypts individual items (like files)
- Items should survive PIN reset
- Perfect forward secrecy is needed

### Code Pattern for Vault Master Key

```python
# Get from session after authentication
session = auth_manager.get_session(session_id)
master_key = session.get_master_key()

# Derive feature-specific key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

salt = load_or_generate_salt()  # Per-feature salt
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=b"YourFeatureName"
)
feature_key = hkdf.derive(master_key)

# Use feature_key for AES-GCM encryption
```

---

## Changelog

- **2025-10-23**: Initial document created to clarify key architecture after user feedback about misleading PIN reset warnings

---

**Related Documentation**:
- [AUTHENTICATION.md](AUTHENTICATION.md) - Authentication system details
- [ARCHITECTURE.md](ARCHITECTURE.md) - Overall system architecture
- [README.md](README.md) - 5-layer encryption pipeline overview
