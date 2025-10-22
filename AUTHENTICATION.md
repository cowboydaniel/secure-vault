# SecureVault Authentication System

## Overview

SecureVault implements a secure authentication system that protects vault access through a multi-layered security approach. The system uses email/password credentials combined with a PIN-based vault unlock mechanism.

## Key Features

- **No PIN Storage**: The PIN is never stored on disk. Verification happens through cryptographic derivation and decryption.
- **Strong Cryptography**: Argon2id key derivation function (KDF) resistant to GPU/ASIC attacks
- **Brute Force Protection**: Exponential backoff and account lockout after failed attempts
- **Session Management**: Secure session tokens with configurable timeout
- **Audit Logging**: All authentication events are logged for security review
- **Account Recovery**: PIN reset capability using email/password verification

## Architecture

### PIN Authentication Design

The authentication system uses a zero-knowledge approach where the PIN is never stored:

#### First-Start Flow

1. User creates account with email + password
2. User sets 6-8 digit PIN
3. System generates random master vault encryption key (256-bit)
4. PIN + random salt → Argon2id → PIN-derived key (KDF)
5. Master vault key encrypted with PIN-derived key → encrypted master key
6. Verification marker (known string) encrypted with master vault key
7. **Stored**: email hash, password hash (Argon2id), encrypted master key, PIN salt, encrypted verification marker
8. **Never Stored**: PIN itself, master vault key in plaintext

#### Login Flow

1. User enters PIN
2. System retrieves PIN salt from database
3. PIN + salt → Argon2id → PIN-derived key
4. Attempt to decrypt encrypted master key with PIN-derived key
5. Decrypt verification marker with master key
6. If verification marker is valid → authentication success
7. If invalid → increment failure counter, rate limit

### Key Derivation Parameters (Argon2id)

```
Algorithm: Argon2id (hybrid mode)
Time Cost: 3 iterations
Memory Cost: 64 MB (65536 KB)
Parallelism: 4 threads
Salt: 16 bytes (cryptographically random per user)
Output: 32 bytes (256-bit key)
```

## Components

### Core Modules

#### `auth_manager.py`
Coordinates authentication operations and session management.

**Key Methods:**
- `authenticate_with_pin(email, pin)`: Authenticate user and create session
- `get_session(session_id)`: Retrieve active session
- `logout(session_id)`: End session and cleanup
- `is_session_valid(session_id)`: Check if session is still valid

#### `user_manager.py`
Handles user account creation and management.

**Key Methods:**
- `create_user(email, password, pin)`: Create new user account
- `verify_password(user_id, password)`: Verify user password
- `reset_pin(user_id, password, new_pin)`: Reset forgotten PIN
- `get_user_by_email(email)`: Lookup user by email

#### `pin_manager.py`
Manages PIN-based cryptography.

**Key Methods:**
- `derive_key_from_pin(pin, salt)`: Derive encryption key from PIN
- `encrypt_master_key(master_key, derived_key, associated_data)`: Encrypt vault key
- `decrypt_master_key(encrypted_key, derived_key, associated_data)`: Decrypt vault key
- `create_verification_marker(master_key, ad)`: Create verification data
- `verify_master_key(master_key, marker, ad)`: Verify decryption succeeded

#### `rate_limiter.py`
Implements brute force protection.

**Features:**
- Per-user attempt tracking
- Exponential backoff (1s, 2s, 4s, 8s, ...)
- Account lockout after N failures (default: 5)
- Time-based lockout release (default: 30 minutes)
- Global rate limiting for unknown emails

#### `auth_database.py`
SQLite database interface for authentication data.

**Tables:**
- `users`: User accounts (email_hash, password_hash, created_at)
- `auth_credentials`: PIN credentials (salt, encrypted_master_key, verification_marker)
- `auth_attempts`: Login attempts (timestamp, success, ip_address, failure_count)
- `sessions`: Active sessions (session_id, created_at, expires_at, last_activity)

### GUI Components

#### `first_start_wizard.py`
Onboarding wizard for initial account setup.

**Features:**
- Multi-page wizard interface
- Email validation
- Password strength meter
- PIN setup with confirmation
- Secure memory wiping for sensitive inputs

#### `login_dialog.py`
PIN-based login screen.

**Features:**
- Email + PIN input
- Error messages for invalid attempts
- Lockout notification with retry time
- "Forgot PIN?" recovery option
- Rate limit error handling

#### `account_recovery_dialog.py`
Account recovery interface for PIN reset.

**Features:**
- Email + password verification
- New PIN setup
- Warning about data loss (new master key generated)
- Secure credential handling

### Security Features

#### Audit Logging
All authentication events are logged with:
- Event type (AUTH_SUCCESS, AUTH_FAILURE, CONFIG_CHANGED)
- Severity level (INFO, WARNING, ERROR)
- Timestamp and user ID
- Additional context (session_id, failure reason, etc.)

#### Secure Memory Handling
Sensitive data is wiped from memory after use:
- PINs wiped after derivation
- Passwords wiped after hashing
- Master keys wiped on session close
- Session tokens securely deleted on logout

#### Session Management
- Configurable session timeout (default: 30 minutes)
- Idle timeout (default: 15 minutes)
- Automatic session expiration
- Session token stored in-memory only (not persisted)

## Usage

### Creating a New Account (GUI)

```python
from auth_manager import AuthManager
from LINUX_GUI.ui.dialogs.first_start_wizard import FirstStartWizard

auth_manager = AuthManager()
wizard = FirstStartWizard(auth_manager=auth_manager)

if wizard.exec() == QDialog.DialogCode.Accepted:
    print("Account created successfully!")
```

### Login (GUI)

```python
from LINUX_GUI.ui.dialogs.login_dialog import LoginDialog

dialog = LoginDialog(auth_manager=auth_manager)

if dialog.exec() == QDialog.DialogCode.Accepted:
    session = dialog.session
    email = dialog.email
    print(f"Logged in as {email}")
```

### Creating a New Account (CLI)

```python
from auth_manager import AuthManager

auth_manager = AuthManager()
user_manager = auth_manager.user_manager

email = "user@example.com"
password = "StrongPassword123!"
pin = "123456"

user_id = user_manager.create_user(email=email, password=password, pin=pin)
print(f"User created with ID: {user_id}")
```

### Login (CLI)

```python
email = "user@example.com"
pin = "123456"

session = auth_manager.authenticate_with_pin(email=email, pin=pin)
print(f"Session ID: {session.session_id}")

# Use the session
master_key = session.get_master_key()

# Logout when done
auth_manager.logout(session.session_id)
```

### PIN Recovery

```python
user = user_manager.get_user_by_email("user@example.com")
password = "StrongPassword123!"
new_pin = "654321"

user_manager.reset_pin(
    user_id=user.user_id,
    password=password,
    new_pin=new_pin
)
print("PIN reset successfully!")
```

## Security Considerations

### PIN Best Practices

- **Avoid Simple Patterns**: No sequential (123456, 987654) or repeating digits (111111)
- **Avoid Common PINs**: No birthdays, common codes (000000, 123456)
- **Length**: Use 6-8 digits for better entropy
- **Uniqueness**: Don't reuse PINs from other accounts

### Password Requirements

- **Minimum Length**: 8 characters
- **Complexity**: Mix of uppercase, lowercase, numbers, special characters
- **Strength**: Use the password strength meter as guidance
- **Uniqueness**: Don't reuse passwords from other accounts

### Account Recovery Warnings

⚠️ **Important**: Resetting your PIN generates a new master key. You will **lose access** to all files encrypted with the old PIN/master key. This is a security trade-off to avoid storing the master key in a password-recoverable form.

**Recommendation**: Always backup your vault data before resetting your PIN.

### Session Security

- Sessions expire after 30 minutes of inactivity
- Use the "Lock Screen" option instead of logout to preserve your session
- Always logout on shared computers
- Session tokens are stored in-memory only (not persisted to disk)

### Threat Model

The authentication system protects against:

- **Brute Force Attacks**: Rate limiting and exponential backoff
- **Credential Stuffing**: Account lockout after multiple failures
- **Timing Attacks**: Constant-time comparison operations
- **Replay Attacks**: Unique session tokens with expiration
- **Memory Forensics**: Secure memory wiping of sensitive data

The system does NOT protect against:

- **Physical Access**: If an attacker has physical access to your computer while unlocked
- **Malware**: If malware is running on your system with sufficient privileges
- **Keyloggers**: If input is captured before reaching the application
- **Rubber-hose Cryptanalysis**: If you are compelled to reveal credentials

## Configuration

### Session Timeout

Edit `auth_manager.py`:

```python
SESSION_TIMEOUT_SECONDS = 30 * 60  # 30 minutes
SESSION_IDLE_TIMEOUT_SECONDS = 15 * 60  # 15 minutes
```

### Rate Limiting

Edit `rate_limiter.py`:

```python
DEFAULT_MAX_ATTEMPTS = 5  # Attempts before lockout
DEFAULT_LOCKOUT_DURATION = 1800  # 30 minutes
```

### Argon2id Parameters

Edit `pin_manager.py`:

```python
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
```

## Testing

Run the authentication test suite:

```bash
python -m pytest test_auth_modules.py -v
```

Test coverage includes:
- PIN encryption/decryption round-trip
- End-to-end authentication flow
- Rate limiter lockout enforcement
- Single account enforcement
- Global rate limiting
- Tamper detection

## Troubleshooting

### Account Locked

**Symptom**: "Account is locked due to too many failed attempts"

**Solution**: Wait 30 minutes for automatic unlock, or contact an administrator to reset the lockout.

### Forgot PIN

**Symptom**: Cannot remember PIN

**Solution**:
1. Click "Forgot PIN?" on login screen
2. Enter email and password
3. Set a new PIN
4. ⚠️ Warning: This generates a new master key and you'll lose access to old encrypted files

### Session Expired

**Symptom**: "Session has expired"

**Solution**: Re-authenticate with your PIN. Sessions expire after 30 minutes for security.

### Invalid Credentials

**Symptom**: "Invalid email or PIN"

**Solution**:
- Double-check email and PIN
- Ensure caps lock is off
- Wait between attempts if rate limited
- Use account recovery if PIN is forgotten

## Future Enhancements

Planned features for future versions:

- Multi-factor authentication (TOTP/hardware keys)
- Biometric authentication (fingerprint, face recognition)
- Passwordless authentication (WebAuthn/FIDO2)
- Cloud backup of encrypted credentials (user-controlled)
- Emergency access codes (printed/stored offline)
- Password-based master key recovery (avoiding data loss on PIN reset)

## References

- [Argon2id Specification](https://github.com/P-H-C/phc-winner-argon2)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Zero-Knowledge Authentication](https://en.wikipedia.org/wiki/Zero-knowledge_proof)

---

**Last Updated**: 2025-10-22
**Version**: 1.0
**Status**: Production Ready
