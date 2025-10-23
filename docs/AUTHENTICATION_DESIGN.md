# Authentication System - Technical Design Document

**Version**: 1.0
**Date**: 2025-10-21
**Status**: Design Phase

## Executive Summary

This document describes the technical design for SecureVault's authentication system, implementing a first-start protocol with email/password account creation and PIN-based login for subsequent access. The critical security requirement is that **the PIN must never be stored** anywhere in the system.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Cryptographic Design](#cryptographic-design)
3. [Database Schema](#database-schema)
4. [System Flow Diagrams](#system-flow-diagrams)
5. [API Specifications](#api-specifications)
6. [Security Analysis](#security-analysis)
7. [Implementation Roadmap](#implementation-roadmap)

---

## 1. Security Architecture

### 1.1 Core Principle: PIN Verification Without Storage

**Problem**: How do we verify a PIN without storing it?

**Solution**: Use the PIN as input to a Key Derivation Function (KDF) to derive an encryption key. This key encrypts the master vault key. Verification happens by attempting decryption - if successful, the PIN was correct.

### 1.2 Key Components

```
┌──────────────────────────────────────────────────────────────┐
│                   AUTHENTICATION SYSTEM                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐       │
│  │   User DB   │   │  Auth       │   │  PIN         │       │
│  │  (SQLite)   │◄──┤  Manager    │◄──┤  Manager     │       │
│  └─────────────┘   └─────────────┘   └──────────────┘       │
│        ▲                  ▲                   ▲              │
│        │                  │                   │              │
│        ▼                  ▼                   ▼              │
│  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐       │
│  │  Session    │   │  Rate       │   │  Audit       │       │
│  │  Manager    │   │  Limiter    │   │  Logger      │       │
│  └─────────────┘   └─────────────┘   └──────────────┘       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 1.3 Security Layers

1. **Email/Password Layer**: Strong password authentication (Argon2id)
2. **PIN Layer**: Quick access authentication (PIN → KDF → Master Key)
3. **Session Layer**: Secure session tokens with expiration
4. **Rate Limiting Layer**: Brute force protection
5. **Audit Layer**: Tamper-evident logging of all events

---

## 2. Cryptographic Design

### 2.1 PIN-Based Authentication Flow

#### First-Start Account Creation

```
User Input:
  ├─ Email: user@example.com
  ├─ Password: SecurePassword123!
  └─ PIN: 123456

Step 1: Generate Master Vault Key
  Master_Key = secure_random(32 bytes)  // 256-bit random key

Step 2: Derive PIN Encryption Key
  PIN_Salt = secure_random(16 bytes)
  PIN_Derived_Key = Argon2id(
    password = PIN,
    salt = PIN_Salt,
    time_cost = 3,
    memory_cost = 65536,  // 64 MB
    parallelism = 4,
    hash_length = 32
  )

Step 3: Encrypt Master Key with PIN-Derived Key
  Encrypted_Master_Key = AES-256-GCM.encrypt(
    plaintext = Master_Key,
    key = PIN_Derived_Key,
    associated_data = email_hash || "master_key"
  )

Step 4: Create Verification Marker
  Verification_Marker_Plaintext = "SECURE_VAULT_AUTH_v1"
  Encrypted_Verification_Marker = AES-256-GCM.encrypt(
    plaintext = Verification_Marker_Plaintext,
    key = Master_Key,
    associated_data = email_hash || "verification"
  )

Step 5: Hash Password for Storage
  Password_Salt = secure_random(16 bytes)
  Password_Hash = Argon2id(
    password = Password,
    salt = Password_Salt,
    time_cost = 3,
    memory_cost = 65536,
    parallelism = 4,
    hash_length = 32
  )

Step 6: Hash Email
  Email_Hash = BLAKE2b(email.lower().strip())

Storage:
  ├─ users table:
  │   ├─ email_hash = Email_Hash
  │   ├─ password_hash = Password_Hash
  │   └─ password_salt = Password_Salt
  │
  └─ auth_credentials table:
      ├─ pin_salt = PIN_Salt
      ├─ encrypted_master_key = Encrypted_Master_Key
      └─ verification_marker = Encrypted_Verification_Marker

NEVER STORED:
  ✗ PIN (123456)
  ✗ Master_Key (plaintext)
  ✗ PIN_Derived_Key
  ✗ Password (plaintext)
```

#### Subsequent Login (PIN Entry)

```
User Input:
  └─ PIN: 123456

Step 1: Retrieve User's Credentials
  Retrieve from database:
    ├─ PIN_Salt
    ├─ Encrypted_Master_Key
    └─ Encrypted_Verification_Marker

Step 2: Derive PIN Encryption Key (Attempt)
  PIN_Derived_Key_Attempt = Argon2id(
    password = PIN,
    salt = PIN_Salt,
    time_cost = 3,
    memory_cost = 65536,
    parallelism = 4,
    hash_length = 32
  )

Step 3: Attempt to Decrypt Master Key
  try:
    Master_Key_Attempt = AES-256-GCM.decrypt(
      ciphertext = Encrypted_Master_Key,
      key = PIN_Derived_Key_Attempt,
      associated_data = email_hash || "master_key"
    )
  except DecryptionError:
    → PIN is incorrect, increment failure counter
    → Apply rate limiting
    → Log failed attempt
    → Return authentication failure

Step 4: Verify Master Key is Correct
  try:
    Verification_Plaintext = AES-256-GCM.decrypt(
      ciphertext = Encrypted_Verification_Marker,
      key = Master_Key_Attempt,
      associated_data = email_hash || "verification"
    )

    if Verification_Plaintext != "SECURE_VAULT_AUTH_v1":
      → Corruption detected, trigger recovery

  except DecryptionError:
    → Corruption detected, trigger recovery

Step 5: Authentication Success
  ├─ Create session token
  ├─ Store Master_Key in secure memory (session duration)
  ├─ Log successful authentication
  └─ Grant access to vault

Memory Cleanup:
  ├─ Wipe PIN from memory
  ├─ Wipe PIN_Derived_Key_Attempt
  └─ Keep Master_Key only in session memory
```

### 2.2 Cryptographic Parameters

#### Argon2id Configuration

```python
ARGON2_CONFIG = {
    'type': 'argon2id',           # Hybrid: d (data-dependent) + i (independent)
    'version': 19,                # Argon2 version 1.3
    'time_cost': 3,               # Number of iterations
    'memory_cost': 65536,         # 64 MB memory (in KiB)
    'parallelism': 4,             # 4 threads
    'salt_length': 16,            # 128-bit salt
    'hash_length': 32,            # 256-bit output
}

# Justification:
# - Argon2id combines resistance to side-channel and GPU attacks
# - 3 iterations + 64MB memory provides strong protection against brute force
# - Parameters meet OWASP recommendations for password hashing
# - Memory-hard design prevents efficient ASIC/GPU attacks
```

#### AES-256-GCM Configuration

```python
AES_GCM_CONFIG = {
    'key_size': 32,               # 256-bit key
    'nonce_size': 12,             # 96-bit nonce (recommended)
    'tag_size': 16,               # 128-bit authentication tag
    'mode': 'GCM',                # Galois/Counter Mode (AEAD)
}

# Justification:
# - AES-256 provides 256-bit security level
# - GCM mode provides both confidentiality and authenticity (AEAD)
# - Authenticated encryption prevents tampering
# - Standards-compliant (NIST SP 800-38D)
```

### 2.3 Security Properties

| Property | Implementation | Verification |
|----------|---------------|--------------|
| **PIN Never Stored** | PIN used only for KDF input, immediately wiped | Code audit, memory dump analysis |
| **Forward Secrecy** | Each session uses unique session token | Session token rotation |
| **Brute Force Resistance** | Argon2id memory-hard KDF + rate limiting | Benchmark attack cost |
| **Tampering Detection** | AEAD (GCM) for all encrypted data | Attempt to modify ciphertext |
| **Replay Protection** | Session tokens expire, nonces never reused | Session timeout enforcement |
| **Side-Channel Resistance** | Constant-time comparisons, Argon2id | Timing analysis |

---

## 3. Database Schema

### 3.1 SQLite Database: `users.db`

#### Table: `users`

```sql
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_hash BLOB NOT NULL UNIQUE,      -- BLAKE2b(email) - 64 bytes
    password_hash BLOB NOT NULL,          -- Argon2id hash - 32 bytes
    password_salt BLOB NOT NULL,          -- 16 bytes
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_locked BOOLEAN DEFAULT 0,          -- Account lockout flag
    failed_attempts INTEGER DEFAULT 0,     -- Failed login counter
    lockout_until TIMESTAMP,               -- Lockout expiration time

    CHECK (failed_attempts >= 0),
    CHECK (is_locked IN (0, 1))
);

CREATE INDEX idx_users_email_hash ON users(email_hash);
```

#### Table: `auth_credentials`

```sql
CREATE TABLE auth_credentials (
    credential_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    pin_salt BLOB NOT NULL,                      -- 16 bytes
    encrypted_master_key BLOB NOT NULL,          -- AES-256-GCM ciphertext + nonce + tag
    verification_marker BLOB NOT NULL,           -- AES-256-GCM ciphertext + nonce + tag
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX idx_auth_credentials_user_id ON auth_credentials(user_id);
```

#### Table: `sessions`

```sql
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,           -- UUID v4 (secure random)
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,                       -- Optional: track login location
    user_agent TEXT,                       -- Optional: track client

    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    CHECK (expires_at > created_at)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

#### Table: `auth_attempts`

```sql
CREATE TABLE auth_attempts (
    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,                       -- NULL if user not found
    email_hash BLOB,                       -- Track attempts even for non-existent users
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    attempt_type TEXT NOT NULL,            -- 'pin', 'password', 'recovery'
    ip_address TEXT,
    failure_reason TEXT,                   -- 'invalid_pin', 'account_locked', etc.

    CHECK (success IN (0, 1)),
    CHECK (attempt_type IN ('pin', 'password', 'recovery'))
);

CREATE INDEX idx_auth_attempts_user_id ON auth_attempts(user_id);
CREATE INDEX idx_auth_attempts_timestamp ON auth_attempts(timestamp);
CREATE INDEX idx_auth_attempts_email_hash ON auth_attempts(email_hash);
```

### 3.2 Data Encryption at Rest

All database files are stored with restrictive permissions:

```bash
chmod 600 users.db        # Owner read/write only
chmod 700 ~/.secure_vault # Directory owner access only
```

Optional: Database-level encryption using SQLCipher (future enhancement).

---

## 4. System Flow Diagrams

### 4.1 First-Start Wizard Flow

```
┌─────────────┐
│   Start     │
│ Application │
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ users.db     │
│ exists?      │
└──────┬───┬───┘
       │   │
      NO  YES
       │   │
       ▼   └─────────────────┐
┌──────────────┐             │
│ First-Start  │             │
│   Wizard     │             │
└──────┬───────┘             │
       │                     │
       ▼                     │
┌──────────────┐             │
│ Welcome      │             │
│ Screen       │             │
└──────┬───────┘             │
       │                     │
       ▼                     │
┌──────────────┐             │
│ Email Input  │             │
│ + Validation │             │
└──────┬───────┘             │
       │                     │
       ▼                     │
┌──────────────┐             │
│ Password     │             │
│ Creation     │             │
│ (Strength    │             │
│  Meter)      │             │
└──────┬───────┘             │
       │                     │
       ▼                     │
┌──────────────┐             │
│ PIN Setup    │             │
│ (6-8 digits, │             │
│  Confirm)    │             │
└──────┬───────┘             │
       │                     │
       ▼                     │
┌──────────────┐             │
│ Create       │             │
│ Account      │             │
│ - Hash email │             │
│ - Hash pwd   │             │
│ - Derive PIN │             │
│   key        │             │
│ - Encrypt    │             │
│   master key │             │
│ - Store all  │             │
└──────┬───────┘             │
       │                     │
       ▼                     │
┌──────────────┐             │
│ Success!     │             │
│ Show Main    │◄────────────┘
│ Application  │
└──────────────┘
```

### 4.2 Login Flow (Subsequent Starts)

```
┌─────────────┐
│   Start     │
│ Application │
└──────┬──────┘
       │
       ▼
┌──────────────┐
│ users.db     │
│ exists?      │
└──────┬───┬───┘
       │   │
      YES NO (go to First-Start)
       │
       ▼
┌──────────────┐
│ Show Login   │
│ Dialog       │
│ (PIN Entry)  │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ User Enters  │
│ PIN          │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Check if     │
│ account      │
│ locked?      │
└──────┬───┬───┘
       │   │
      NO  YES
       │   │
       │   ▼
       │ ┌──────────────┐
       │ │ Show Lockout │
       │ │ Message      │
       │ │ (Try again   │
       │ │  in X min)   │
       │ └──────────────┘
       │
       ▼
┌──────────────┐
│ Derive PIN   │
│ key (Argon2) │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Decrypt      │
│ Master Key   │
└──────┬───┬───┘
       │   │
   SUCCESS FAIL
       │   │
       │   ▼
       │ ┌──────────────┐
       │ │ Increment    │
       │ │ Failure      │
       │ │ Counter      │
       │ └──────┬───────┘
       │        │
       │        ▼
       │ ┌──────────────┐
       │ │ >= 5 fails?  │
       │ └──────┬───┬───┘
       │        │   │
       │       YES NO
       │        │   │
       │        ▼   │
       │ ┌──────────────┐ │
       │ │ Lock Account │ │
       │ │ (30 minutes) │ │
       │ └──────────────┘ │
       │                  │
       │   ┌──────────────┘
       │   ▼
       │ ┌──────────────┐
       │ │ Show Error   │
       │ │ "Invalid PIN"│
       │ │ (X attempts  │
       │ │  remaining)  │
       │ └──────────────┘
       │
       ▼
┌──────────────┐
│ Verify       │
│ Master Key   │
│ (Decrypt     │
│  Marker)     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Create       │
│ Session      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Show Main    │
│ Application  │
└──────────────┘
```

### 4.3 Rate Limiting Flow

```
Failed Login Attempt
       │
       ▼
┌──────────────┐
│ failed_      │
│ attempts++   │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────┐
│ Apply Exponential Backoff:   │
│                               │
│ Attempt 1: 0s delay           │
│ Attempt 2: 1s delay           │
│ Attempt 3: 2s delay           │
│ Attempt 4: 4s delay           │
│ Attempt 5: 8s delay           │
│ Attempt 6+: Lock account      │
│            (30 min)           │
└──────┬───────────────────────┘
       │
       ▼
┌──────────────┐
│ Update DB:   │
│ - attempts   │
│ - is_locked  │
│ - lockout_   │
│   until      │
└──────────────┘
```

---

## 5. API Specifications

### 5.1 Module: `user_manager.py`

```python
class UserManager:
    """Manages user accounts and credentials."""

    def create_user(
        self,
        email: str,
        password: str,
        pin: str
    ) -> Result[UserId, Error]:
        """
        Create a new user account.

        Args:
            email: User's email address (validated)
            password: User's password (min 12 chars, complexity checked)
            pin: User's PIN (6-8 digits)

        Returns:
            Success(user_id) or Error

        Security:
            - Email is hashed before storage (BLAKE2b)
            - Password is hashed with Argon2id
            - PIN is used to derive key, then immediately wiped
            - Master vault key is generated (256-bit random)
            - Master key encrypted with PIN-derived key

        Raises:
            ValidationError: Invalid input
            DatabaseError: Database operation failed
        """
        pass

    def get_user_by_email(
        self,
        email: str
    ) -> Result[User, Error]:
        """Retrieve user by email (hashed lookup)."""
        pass

    def update_password(
        self,
        user_id: int,
        old_password: str,
        new_password: str
    ) -> Result[None, Error]:
        """Update user's password."""
        pass

    def reset_pin(
        self,
        user_id: int,
        password: str,
        new_pin: str
    ) -> Result[None, Error]:
        """
        Reset user's PIN (requires password verification).

        Process:
            1. Verify password
            2. Decrypt master key with old PIN (already in session)
            3. Generate new PIN salt
            4. Derive new PIN key
            5. Encrypt master key with new PIN key
            6. Update database
        """
        pass
```

### 5.2 Module: `auth_manager.py`

```python
class AuthManager:
    """Handles authentication and session management."""

    def authenticate_with_pin(
        self,
        email: str,
        pin: str
    ) -> Result[Session, AuthError]:
        """
        Authenticate user with PIN.

        Args:
            email: User's email
            pin: User's PIN

        Returns:
            Success(Session) or AuthError

        Security Flow:
            1. Hash email, lookup user
            2. Check if account locked
            3. Retrieve PIN salt
            4. Derive PIN key (Argon2id)
            5. Attempt to decrypt master key
            6. Verify master key by decrypting verification marker
            7. If successful: create session, reset failure counter
            8. If failed: increment failure counter, apply rate limiting

        Errors:
            - InvalidCredentialsError: Wrong PIN
            - AccountLockedError: Too many failed attempts
            - DatabaseError: DB operation failed
        """
        pass

    def authenticate_with_password(
        self,
        email: str,
        password: str
    ) -> Result[Session, AuthError]:
        """Authenticate with email + password (for recovery)."""
        pass

    def validate_session(
        self,
        session_id: str
    ) -> Result[Session, Error]:
        """Check if session is valid and not expired."""
        pass

    def logout(
        self,
        session_id: str
    ) -> Result[None, Error]:
        """
        End user session.

        Security:
            - Delete session from database
            - Wipe master key from memory
            - Log logout event
        """
        pass
```

### 5.3 Module: `pin_manager.py`

```python
class PINManager:
    """Handles PIN-related cryptographic operations."""

    def derive_key_from_pin(
        self,
        pin: str,
        salt: bytes
    ) -> bytes:
        """
        Derive encryption key from PIN using Argon2id.

        Args:
            pin: User's PIN (6-8 digits)
            salt: Random salt (16 bytes)

        Returns:
            32-byte derived key

        Security:
            - Uses Argon2id with recommended parameters
            - PIN is wiped from memory after derivation
            - Constant-time operation
        """
        pass

    def encrypt_master_key(
        self,
        master_key: bytes,
        pin_derived_key: bytes,
        associated_data: bytes
    ) -> bytes:
        """
        Encrypt master vault key with PIN-derived key.

        Returns:
            Encrypted data (ciphertext || nonce || tag)
        """
        pass

    def decrypt_master_key(
        self,
        encrypted_master_key: bytes,
        pin_derived_key: bytes,
        associated_data: bytes
    ) -> Result[bytes, DecryptionError]:
        """
        Decrypt master vault key.

        Returns:
            Success(master_key) or DecryptionError (wrong PIN)
        """
        pass

    def validate_pin_format(
        self,
        pin: str
    ) -> Result[None, ValidationError]:
        """
        Validate PIN meets requirements.

        Requirements:
            - 6-8 digits only
            - No repeating digits (e.g., 111111)
            - No sequential digits (e.g., 123456)
            - Not common PINs (1234, 0000, etc.)
        """
        pass
```

### 5.4 Module: `rate_limiter.py`

```python
class RateLimiter:
    """Implements brute force protection."""

    def check_rate_limit(
        self,
        user_id: int
    ) -> Result[None, RateLimitError]:
        """
        Check if user can attempt authentication.

        Returns:
            Success if allowed, RateLimitError if locked/rate limited
        """
        pass

    def record_failed_attempt(
        self,
        user_id: int
    ) -> None:
        """
        Record failed authentication attempt.

        Logic:
            - Increment failure counter
            - Apply exponential backoff: 2^(attempts-2) seconds
            - Lock account after 5 failures (30 minute lockout)
        """
        pass

    def record_successful_attempt(
        self,
        user_id: int
    ) -> None:
        """Reset failure counter on successful auth."""
        pass

    def is_locked(
        self,
        user_id: int
    ) -> bool:
        """Check if account is currently locked."""
        pass

    def unlock_account(
        self,
        user_id: int
    ) -> None:
        """Manually unlock account (admin function)."""
        pass
```

---

## 6. Security Analysis

### 6.1 Threat Model

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| **PIN Brute Force** | Argon2id (expensive KDF) + rate limiting + account lockout | Low - 10 attempts take ~30 seconds with lockout |
| **Database Theft** | PIN not stored, master key encrypted, all passwords hashed | Low - attacker needs PIN to decrypt master key |
| **Memory Dump** | Secure memory wiping, short-lived plaintext exposure | Medium - timing window for memory attack |
| **Timing Attacks** | Constant-time comparisons, Argon2id natural timing variation | Low - Argon2id provides some timing resistance |
| **Replay Attacks** | Session tokens expire, nonces never reused | Low - sessions timeout, GCM prevents replay |
| **Physical Access** | Database file permissions (600), OS-level security | Medium - relies on OS file protection |
| **Insider Attack** | Audit logging, tamper-evident logs | Medium - insider with DB access can't decrypt without PIN |

### 6.2 Attack Cost Analysis

#### Brute Force Attack on PIN (Offline)

Assumptions:
- Attacker steals `users.db` file
- Attacker knows Argon2id parameters
- Attacker has access to GPU farm (100 GPUs, RTX 4090)

```
PIN Space: 10^6 (000000 - 999999) = 1,000,000 possible PINs

Argon2id Performance:
- Single RTX 4090: ~100 hashes/second (64MB memory requirement)
- GPU farm (100 GPUs): ~10,000 hashes/second

Time to exhaust PIN space:
  1,000,000 PINs / 10,000 hashes/sec = 100 seconds = ~1.7 minutes

Cost:
  100x RTX 4090 @ $1.50/hr each = $150/hr
  Attack duration: 1.7 minutes = $4.25 total cost

Conclusion: 6-digit PIN is NOT secure against offline attack!
```

**Mitigation Strategies**:

1. **Increase to 8-digit PIN**: 100,000,000 space → ~2.7 hours attack time
2. **Increase Argon2id memory cost**: 256MB → ~10x slower → ~17 minutes for 6-digit
3. **Require password + PIN**: Must break password hash first (much harder)
4. **HSM integration**: Store master key in HSM, requires online attack (rate limited)

**Recommended**: Enforce 8-digit PIN minimum + increase memory cost to 128MB.

#### Brute Force Attack on Password (Offline)

Assumptions:
- Password: 12 characters, mixed case + numbers + symbols
- Character space: 72 characters (a-z, A-Z, 0-9, 10 symbols)
- Same GPU farm as above

```
Password Space: 72^12 ≈ 1.9 × 10^22

Time to exhaust 1% of password space:
  1.9 × 10^20 / 10,000 = 1.9 × 10^16 seconds
  = 6 × 10^8 years

Conclusion: Strong password is secure against brute force.
```

### 6.3 Security Best Practices for Users

1. **Strong Password**: Minimum 12 characters, use password manager
2. **Strong PIN**: 8 digits, avoid birthdays/patterns/sequential numbers
3. **Device Security**: Full disk encryption, strong OS password
4. **Physical Security**: Don't leave device unattended while logged in
5. **Network Security**: Only use trusted networks (VPN recommended)

### 6.4 Security Recommendations for Implementation

1. **Increase PIN to 8 digits minimum** (reduces brute force risk)
2. **Increase Argon2id memory to 128MB** (further slows GPU attacks)
3. **Implement automatic logout after 15 minutes inactivity**
4. **Add optional 2FA** (TOTP) for additional security layer
5. **Consider HSM integration** for master key storage (prevents offline attacks)
6. **Encrypt database with SQLCipher** (additional layer of protection)

---

## 7. Implementation Roadmap

### Phase 1: Core Authentication (Week 1-2)

- [ ] Database schema implementation
- [ ] `user_manager.py` - user CRUD operations
- [ ] `auth_manager.py` - authentication logic
- [ ] `pin_manager.py` - PIN cryptography
- [ ] `rate_limiter.py` - brute force protection
- [ ] Unit tests for all modules

### Phase 2: GUI Integration (Week 3)

- [ ] `first_start_wizard.py` - account creation UI
- [ ] `login_dialog.py` - PIN login UI
- [ ] `account_recovery_dialog.py` - recovery UI
- [ ] Integration with `LINUX_GUI/main.py`
- [ ] Update `Header` widget with user info

### Phase 3: CLI Integration (Week 4)

- [ ] `cli_auth.py` - CLI authentication wrapper
- [ ] Modify `main.py` to require authentication
- [ ] Session token storage for CLI
- [ ] CLI-specific user flows

### Phase 4: Security & Testing (Week 5)

- [ ] Audit logging integration
- [ ] Secure memory wiping implementation
- [ ] Session timeout and auto-lock
- [ ] Security testing (brute force simulation)
- [ ] Penetration testing

### Phase 5: Documentation & Review (Week 6)

- [ ] User documentation
- [ ] Developer documentation
- [ ] Security audit
- [ ] Code review
- [ ] Performance benchmarking

---

## Appendix A: Code Examples

### Example: First-Start Account Creation

```python
from user_manager import UserManager
from pin_manager import PINManager
import secrets

def create_first_account(email: str, password: str, pin: str):
    """Create the first user account."""

    # Validate inputs
    if not validate_email(email):
        raise ValidationError("Invalid email format")
    if not validate_password_strength(password):
        raise ValidationError("Password too weak")
    if not PINManager().validate_pin_format(pin):
        raise ValidationError("PIN does not meet requirements")

    # Generate master vault key
    master_key = secrets.token_bytes(32)  # 256-bit random key

    # Generate PIN salt and derive key
    pin_salt = secrets.token_bytes(16)
    pin_manager = PINManager()
    pin_derived_key = pin_manager.derive_key_from_pin(pin, pin_salt)

    # Encrypt master key with PIN-derived key
    email_hash = hashlib.blake2b(email.lower().encode()).digest()
    associated_data = email_hash + b"master_key"
    encrypted_master_key = pin_manager.encrypt_master_key(
        master_key,
        pin_derived_key,
        associated_data
    )

    # Create verification marker
    verification_plaintext = b"SECURE_VAULT_AUTH_v1"
    verification_ad = email_hash + b"verification"
    encrypted_verification = encrypt_aes_gcm(
        verification_plaintext,
        master_key,
        verification_ad
    )

    # Hash password
    password_salt = secrets.token_bytes(16)
    password_hash = hash_password_argon2id(password, password_salt)

    # Store in database
    user_manager = UserManager()
    user_id = user_manager.create_user(
        email_hash=email_hash,
        password_hash=password_hash,
        password_salt=password_salt,
        pin_salt=pin_salt,
        encrypted_master_key=encrypted_master_key,
        verification_marker=encrypted_verification
    )

    # Wipe sensitive data from memory
    secure_wipe(pin)
    secure_wipe(pin_derived_key)
    secure_wipe(master_key)
    secure_wipe(password)

    return user_id
```

### Example: PIN Login

```python
from auth_manager import AuthManager
from pin_manager import PINManager

def login_with_pin(email: str, pin: str):
    """Authenticate user with PIN."""

    auth_manager = AuthManager()

    # Check rate limiting
    user = auth_manager.get_user_by_email(email)
    if user.is_locked:
        raise AccountLockedError(
            f"Account locked. Try again at {user.lockout_until}"
        )

    # Retrieve credentials
    credentials = auth_manager.get_credentials(user.user_id)

    # Derive PIN key
    pin_manager = PINManager()
    pin_derived_key = pin_manager.derive_key_from_pin(
        pin,
        credentials.pin_salt
    )

    # Attempt to decrypt master key
    try:
        master_key = pin_manager.decrypt_master_key(
            credentials.encrypted_master_key,
            pin_derived_key,
            user.email_hash + b"master_key"
        )
    except DecryptionError:
        # PIN is incorrect
        auth_manager.record_failed_attempt(user.user_id)
        secure_wipe(pin)
        secure_wipe(pin_derived_key)
        raise InvalidCredentialsError("Invalid PIN")

    # Verify master key by decrypting verification marker
    try:
        verification = decrypt_aes_gcm(
            credentials.verification_marker,
            master_key,
            user.email_hash + b"verification"
        )
        assert verification == b"SECURE_VAULT_AUTH_v1"
    except (DecryptionError, AssertionError):
        raise CorruptionError("Master key verification failed")

    # Authentication successful - create session
    session = auth_manager.create_session(
        user_id=user.user_id,
        master_key=master_key
    )

    # Wipe PIN from memory
    secure_wipe(pin)
    secure_wipe(pin_derived_key)

    # Log successful authentication
    audit_logger.log_auth_success(user.user_id, "pin")

    return session
```

---

## Appendix B: Security Checklist

- [ ] PIN is never stored in database
- [ ] PIN is never logged
- [ ] PIN is wiped from memory after use
- [ ] Master key is wiped from memory on logout
- [ ] Password is wiped from memory after hashing
- [ ] All cryptographic operations use constant-time comparisons
- [ ] Argon2id parameters meet OWASP recommendations
- [ ] AES-GCM nonces are never reused
- [ ] Database files have restrictive permissions (600)
- [ ] Session tokens are cryptographically random
- [ ] Sessions expire after timeout
- [ ] Rate limiting prevents brute force
- [ ] Account lockout after 5 failed attempts
- [ ] All authentication events are audit logged
- [ ] Audit logs are tamper-evident
- [ ] Error messages don't leak information
- [ ] Timing attacks are mitigated
- [ ] SQL injection is prevented (parameterized queries)
- [ ] Input validation on all user inputs

---

**Document Revision History**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-10-21 | Claude Code | Initial technical design |

---

**End of Technical Design Document**
