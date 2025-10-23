# Secure Vault CLI Guide

The Secure Vault command-line interface provides a scripted path for operating the
five-layer encryption pipeline while preserving the same accessibility and
security guarantees available in the graphical client. This guide captures the
completed documentation work for phase 1.4, covering user workflows, developer
integration points, API references, and human-factors guidance.

## 1. User Workflows

### 1.1 Quick Start
- Authenticate with `python main.py` and follow the on-screen prompts.
- Run `python main.py --help` to view the full command catalogue. Every
  sub-command now includes detailed descriptions, argument defaults, and
  automation tips.
- Encrypt a file non-interactively:
  ```bash
  python main.py encrypt --input secrets.tar.gz --shares 7 --threshold 4
  ```
- Decrypt, list, and share files by invoking `python main.py decrypt`,
  `python main.py list`, and `python main.py share <file_id> <email>`.

### 1.2 Configuration Files
The CLI reads optional configuration files supplied with `--config PATH`. The
loader accepts JSON, TOML, or INI formats and updates the runtime configuration
before the application starts. Supported keys are grouped into `system`,
`storage`, and `security` sections. Example JSON:

```json
{
  "system": {
    "config_dir": "~/securevault-config",
    "log_dir": "~/securevault-config/logs",
    "verbose_logging": true
  },
  "storage": {
    "extra_safe_directories": ["/mnt/securevault"],
    "compression_enabled": false
  },
  "security": {
    "auto_lock_timeout": 900
  }
}
```

Apply the configuration during execution:

```bash
python main.py --config ~/.config/securevault.json encrypt --input payroll.db
```

When a configuration file cannot be parsed the CLI renders a structured error
message with a remediation hint and exits with status code 2.

### 1.3 Progress Indicators
Encryption and decryption emit 50-character progress bars that surface the
current layer activity. A summary of throughput, layer completion, and security
posture is printed once the operation finishes. Progress bars remain active when
the CLI is invoked programmatically, enabling log scraping by automated jobs.

### 1.4 Error Reporting
Operational failures are now surfaced with consistent error banners:

```
❌ No user registered with email ops@example.com
   💡 Confirm the recipient has completed onboarding.
```

The prefixed icon enables quick parsing in terminal transcripts and
accessibility tools. Additional hints outline the most common remediations.

## 2. Developer Integration

### 2.1 Automation Patterns
- Suppress the banner and capability probes with `--no-banner` to keep batch job
  logs concise.
- Combine `--config` with environment-specific templates to switch storage
  directories or disable compression in CI environments.
- Use the returned exit codes (0 success, 1 functional failure, 2
  configuration error, 130 user-cancelled) to wire health checks in deployment
  pipelines.

### 2.2 Embedding in Python
Developers can drive the CLI features by importing helper functions from
`main.py`. For example, use `encrypt_file_interactive(session=..., file_path=...)`
inside automated workflows to reuse the progress handling and structured
reporting.

## 3. API Reference Snapshot

- `cli_config.apply_cli_configuration(path)` — Parses the configuration file and
  applies overrides to `config.default_config`, `StorageConfig`, and
  `SecurityConfig`.
- `main.render_cli_error(message, hint=None)` — Formats CLI-facing errors with a
  consistent prefix and optional remediation hint.
- `main.encrypt_file_interactive(..., file_path=None, total_shares=None,
  threshold=None)` — Executes the encryption pipeline, now accepting optional
  CLI arguments.

Refer to `config.apply_configuration_overrides` for the complete list of
recognised keys.

## 4. Accessibility, Localization, and Screen-Capture Guidance

- **Accessibility:** Progress messages include emoji and descriptive language so
  screen readers can differentiate success, warnings, and failures. Error hints
  avoid colour-only signalling.
- **Localization/I18n:** All CLI strings are free of string interpolation with
  embedded markup, simplifying future translation passes. When localising, update
  `main.render_cli_error` and the argparse configuration so new locales inherit
  the consistent format.
- **Screen-Capture Protection:** For terminals that support it, disable scrollback
  logging when handling sensitive data. Pair CLI operations with the GUI's
  screen-capture protections to guard subsequent graphical workflows. The CLI
  avoids echoing secrets and wipes interactive prompts immediately after use.

## 5. Regression Coverage

Phase 1.4 expands GUI automation coverage by extending `tests/test_gui_regression.py`
with new assertions that validate error messaging behaviour for authentication
failures. This ensures parity between the CLI and GUI when surfacing credential
issues and anchors the accessibility improvements in automated checks.

---

This guide satisfies the documentation deliverables outlined in the roadmap by
uniting user-facing instructions, developer playbooks, API notes, and inclusive
operational guidance.
