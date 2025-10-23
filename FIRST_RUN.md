# First Run Setup

If you're getting a "tampering detected" error on first run, you need to initialize the security state.

## Quick Fix

Run this command to clear any existing security state:

```bash
# Remove state directory (creates fresh instance)
rm -rf ~/.config/secure_vault/
rm -rf ~/.local/share/secure_vault/

# Also remove any database files in the repo directory
cd ~/secure_vault  # or wherever you cloned the repo
rm -f users.db
rm -f *.db
```

Then run the application again:

```bash
python3 LINUX_GUI/main.py
# or
python3 main.py
```

## What's Happening?

SecureVault uses an "instance guard" security feature that binds the authentication database to a specific installation. This prevents:

- Copying the database to another machine
- Restoring old database backups (replay attacks)
- Tampering with the authentication system

On **first run**, the instance guard must be in "fresh" state to allow initial setup. If state files exist from a previous installation or testing, the guard blocks initialization as a security precaution.

## Prevention

The following files should **never** be committed to git or copied between installations:

- `~/.config/secure_vault/instance_state.json` - Instance guard state
- `~/.local/share/secure_vault/*` - User data directory
- `users.db` - Authentication database
- `*.db` - Any database files

These are security-sensitive files unique to each installation.

> **Important:** SecureVault now treats the guard state file as mandatory once the authentication database has been provisioned. If `instance_state.json` is deleted while `users.db` (or any other authentication database) remains, the application will immediately enter lockdown and require manual recovery.

## Development/Testing

If you're a developer and need to frequently reset the system:

```bash
# Quick reset script
#!/bin/bash
rm -rf ~/.config/secure_vault/
rm -rf ~/.local/share/secure_vault/
rm -f ~/secure_vault/users.db
echo "SecureVault state cleared"
```

Save this as `reset_vault.sh` and run `chmod +x reset_vault.sh` to make it executable.
