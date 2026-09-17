# Secure Vault: Experimental Multi-Layer Encryption System

Secure Vault is a research and educational implementation of a multi-layer
encryption system. It combines information dispersal, one-time-pad-style
encryption, post-quantum cryptography, an experimental custom 512-bit cipher,
and a storage layer. **The current source tree is not production-ready and
must not be used to protect sensitive data.**

## 🔒 Security Features

## 📣 Project Status

Secure Vault is under active development. The current source does not compile,
the test suite does not complete collection, and no supported release is
available. Feature descriptions in this README describe the intended design,
not validated security guarantees. See [Current Development Status](#current-development-status)
and the [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md) for known blockers.

### Automatic Backup Security
- **End-to-End Encryption**: All backups are encrypted before being written to disk
- **Secure Key Handling**: Backup keys are generated using cryptographically secure RNG
- **Tamper Evidence**: Backups include integrity checks to detect modification
- **Secure Deletion**: Old backups are securely removed when rotated out
- **Access Control**: Backup files have strict file permissions (600)

### Recovery Security
- **Passphrase Protection**: Backups require the original passphrase for restoration
- **Secure Memory**: Sensitive data is wiped from memory after use
- **Verification**: Backups can be verified without full restoration
- **Partial Recovery**: Supports restoring only specific keys when needed

## 🔐 Security Layers

1. **Information Dispersal Algorithm (IDA)**
   - Splits data into multiple shares using Reed-Solomon encoding
   - Provides fault tolerance through redundancy
   - Requires only a threshold of shares to reconstruct original data

2. **One-Time Pad (OTP)**
   - Theoretically unbreakable when used correctly
   - Uses cryptographically secure random number generation
   - Implements perfect secrecy as per Shannon's theorem
   - **Security Analysis**:
     - Keys are generated using `os.urandom()` for cryptographically secure randomness
     - Each key is used exactly once and then securely zeroed from memory
     - Implements constant-time XOR operations to prevent timing attacks
     - Each share is encrypted with a unique, independent key

3. **ML-KEM-1024 (Post-Quantum)**
   - Quantum-resistant key encapsulation mechanism
   - Based on lattice-based cryptography
   - NIST-selected algorithm for post-quantum security

4. **Custom 512-bit Cipher**
   - **Research Implementation**: This is an experimental cipher for research and educational purposes only
   - **Not Production-Ready**: Not intended for securing sensitive or production data
   - **Security Notice**: Custom ciphers should always be reviewed by professional cryptographers before use
   - **Block Size**: 512-bit block size for academic exploration of large block ciphers
   - **Purpose**: Designed for studying cryptographic principles and potential vulnerabilities
   - **Warning**: Use standardized, well-reviewed algorithms (like AES) for any real-world security needs

5. **Secure Storage Layer**
   - Optional steganography support
   - Secure metadata handling
   - Anti-forensic techniques

## 🚀 Features

### Security Features
- **Theoretical Security**: Implements information-theoretically secure encryption (OTP layer)
- **Quantum Resistance**: ML-KEM-1024 ready for post-quantum computing era
- **Fault Tolerant**: Data recovery with partial shares using Reed-Solomon encoding
- **Defense in Depth**: 5 independent security layers
- **Perfect Forward Secrecy**: One-time pad ensures keys cannot be reused

### Key Management
- **Automatic Key Backup**: Secure, encrypted backups with AES-256-GCM
- **HSM Integration**: Hardware Security Module support for key storage
- **Key Rotation**: Automated key lifecycle management (in development)
- **Secure Memory**: Automatic memory zeroing for sensitive data

### Data Integrity & Audit
- **Multi-Algorithm Integrity**: SHA3-512, BLAKE2b, HMAC verification
- **Tamper-Evident Logging**: Chain-hashed audit trails
- **Metadata Protection**: Encrypted metadata storage with SQLite
- **Corruption Detection**: Chunked integrity checking for large files

### Operational Hardening
- Review the [Security Configuration Baseline](SECURITY_CONFIG.md) for required file permissions, environment variables, and the operator hardening checklist.
- Follow the [Deployment Runbook](DEPLOYMENT_RUNBOOK.md) so operators acknowledge the checklist before production rollouts.

### Performance & Optimization
- **High Performance**: Hardware RNG support (RDRAND/RDSEED, TPM)
- **Smart Compression**: Auto-selecting compression (LZ4, Zstandard, zlib)
- **Comprehensive Benchmarking**: Layer-by-layer performance analysis
- **Cross-Platform**: Linux, Windows, macOS support

### Quality & Validation
- **Cryptographic Validation**: S-box quality analysis, randomness testing
- **NIST SP 800-22 Coverage**: Forward and reverse cumulative sums tests with configurable health thresholds surface entropy regressions quickly
- **Extensive Testing**: Unit tests, integration tests, property-based testing
- **Security Analysis**: Built-in crypto property validation
- **Configurable Security**: Adjust parameters for your threat model

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/secure_vault.git
   cd secure_vault
   ```

2. Install dependencies:
   ```bash
   ./install_dependencies.sh
   ```

3. Build the required libraries:
   ```bash
   ./build_liboqs.sh
   ```

### First-Time Setup

If you encounter a "tampering detected" error on first run, see [FIRST_RUN.md](FIRST_RUN.md) for initialization instructions. This is a security feature that ensures each installation is uniquely bound to prevent database tampering.

## 🛠️ Usage

For an in-depth walkthrough of configuration files, automation patterns, and
accessibility guidance, refer to the [CLI Guide](CLI_GUIDE.md).

### Encrypt a file
```bash
python main.py encrypt --input sensitive_document.pdf --output encrypted.sec
```

### Decrypt a file
```bash
python main.py decrypt --input encrypted.sec --output restored_document.pdf
```

### List encrypted files
```bash
python main.py list
```

### Run benchmarks
```bash
python main.py benchmark
```

### Key Backup and Recovery

Secure Vault includes an advanced automatic backup system for cryptographic keys:

#### Automatic Backups
- **On-Demand Backups**: Create encrypted backups of keys at any time
- **Scheduled Backups**: Regular automatic backups (configurable interval)
- **Shutdown Backups**: Final backup when the application closes
- **Metadata Protection**: Automatic backup of key metadata on changes

#### Recovery Features
- **Automatic Recovery**: Self-healing from data corruption on startup
- **Backup Verification**: Verify backup integrity without restoring
- **Selective Restoration**: Restore specific keys from backup
- **Backup Rotation**: Configurable retention policy for old backups

#### Configuration
Configure backup settings when initializing the KeyManager:

```python
from key_manager import KeyManager, KeyType

# Initialize with backup configuration
key_manager = KeyManager({
    'backup_enabled': True,      # Enable automatic backups
    'backup_dir': 'backups',     # Directory to store backups
    'backup_retention': 5,       # Number of backups to keep
    'backup_schedule': 24,       # Backup interval in hours (0 to disable)
    'backup_passphrase': None,   # Optional: passphrase for backups
})
```

#### Backup File Security
- **Encryption**: Backups are encrypted with AES-256-GCM
- **Key Derivation**: Uses PBKDF2 with 600,000 iterations
- **Secure Storage**: Backup files have restricted permissions (600)
- **No Plaintext Storage**: Passphrases are never stored on disk

## 🏗️ Project Structure

### Core Encryption Layers
- `main.py`: Command-line interface and main application logic
- `pipeline.py`: Core multi-layer encryption/decryption pipeline
- `ida_layer.py`: Information Dispersal Algorithm implementation (Layer 1)
- `otp_layer.py`: One-Time Pad implementation (Layer 2)
- `mlkem_layer.py`: Post-quantum ML-KEM implementation (Layer 3)
- `custom_cipher.py`: Custom 512-bit cipher implementation (Layer 4)
- `storage_layer.py`: Secure storage implementation (Layer 5)

### Key Management & Security
- `key_manager.py`: Secure key management with automatic backup and recovery
- `audit_logger.py`: Security event logging and tamper-evident audit trails
- `integrity_checker.py`: Data integrity verification with multi-algorithm hashing
- `crypto_validation.py`: Cryptographic property validation (S-box quality, randomness testing)

### Utilities & Support
- `metadata_manager.py`: Secure metadata storage and management (SQLite-based)
- `compression.py`: Multi-algorithm compression (LZ4, Zstandard, zlib)
- `benchmark.py`: Comprehensive performance benchmarking suite
- `crypto_utils.py`: Cryptographic utilities and helpers
- `config.py`: Configuration settings
- `constants.py`: System constants and enums

### Entropy & Random Number Generation
- `entropy_pool.py`: Fortuna-like entropy accumulator with multiple pools
- `entropy_monitor.py`: Entropy quality monitoring and validation, including bidirectional cumulative sums randomness testing and health scoring penalties when thresholds are breached
- `hardware_rng.py`: Hardware RNG integration (RDRAND/RDSEED, TPM)
- `rng_manager.py`: Random number generation coordination

### Mathematical Foundations
- `galois_field.py`: GF(2^512) field arithmetic for IDA
- `secure_memory.py`: Secure memory handling with zeroing
- `secure_storage.py`: Secure file operations

### Testing & Validation
- `test_custom_cipher.py`: Comprehensive cipher test suite
- `test_ida.py`: Information Dispersal Algorithm tests
- `test_otp.py`: One-Time Pad layer tests
- `test_entropy_monitor.py`: Entropy system tests
- `test_hardware_rng.py`: Hardware RNG tests
- `test_security.py`: Security property tests

### Documentation
- `ARCHITECTURE.md`: Complete system architecture documentation
- `SECURITY.md`: Security policy and best practices
- `SECURITY_REVIEW.md`: Current security review and assurance status
- `v1_roadmap.md`: Development roadmap and progress tracking

## 🔍 Current Development Status

The repository contains implementations and tests for the core encryption
pipeline, authentication, recovery, backup, GUI, entropy, platform-parity, and
key-management features. Their presence does not currently establish that they
work together or meet their stated security properties.

### 🚫 Release blockers

- `python -m compileall -q .` fails on multiple source and test files.
- `pytest -q` stops during collection with ten errors and three skipped tests.
- Tests require SciPy, but it is not declared in `requirements.txt`.
- Qt tests require native graphical libraries that are not provisioned in the
  assessment environment.
- The GitHub Actions workflow performs dependency auditing only; it does not
  compile the project, run tests, lint, or type-check the code.

### ✅ What is present

- Implementations for the five-layer encryption design and associated storage.
- Authentication, recovery, delegation, cloud-backup, MFA, and emergency-code
  modules.
- A Qt GUI and cross-platform integration helpers.
- A broad test suite covering cryptography, storage, authentication, entropy,
  security workflows, and GUI behavior.
- Deployment, architecture, security, and operational documentation.

### Next steps

1. Repair the syntax and source-encoding errors.
2. Make the dependency manifest complete and reproducible.
3. Restore a passing test baseline, including headless GUI configuration.
4. Add compilation, tests, linting, and type checking to pull-request CI.
5. Complete security review and release validation before assigning a release
   version.

## 📊 Benchmarks

Run the built-in benchmarks to test system performance:

```bash
python benchmark.py
```

## 🔒 Security Considerations

### One-Time Pad Implementation Security

The OTP implementation has been analyzed for security compliance:

#### Security Strengths:
- **Key Generation**: Uses `os.urandom()` which is cryptographically secure on modern operating systems
- **Key Usage**: Each key is used exactly once and then securely erased from memory
- **Encryption Process**:
  - Implements constant-time XOR operations to prevent timing attacks
  - Each share is processed with an independent key
  - Proper error handling to prevent partial key exposure

#### Security Considerations:
- **Key Management**: 
  - Keys are stored in memory during processing
  - Memory protection mechanisms are in place to prevent key leakage
- **Entropy Source**:
  - Relies on system's cryptographic random number generator
  - No additional entropy mixing is performed

#### Best Practices:
- Always ensure your system's random number generator is properly seeded
- Monitor system entropy levels in production environments
- Use secure memory regions for key storage when available

### General Security Guidelines
- Always keep your encryption keys secure
- Use strong, unique passwords for key generation
- Regularly update the software to get the latest security patches
- Consider physical security of encrypted shares
- Follow the principle of least privilege for file access

## 🤝 Contributing

Contributions are welcome! Please read our [Contribution Guidelines](CONTRIBUTING.md) before submitting pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.

## 📚 Resources

- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Shannon's Theory of Secrecy Systems](https://ieeexplore.ieee.org/document/6769090)
- [Reed-Solomon Error Correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)

## 📞 Support

For support, please open an issue on the GitHub repository.

---

*This project is for educational and research purposes only. The authors make no warranties regarding the security of this implementation.*
