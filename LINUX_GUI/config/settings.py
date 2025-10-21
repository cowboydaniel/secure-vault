"""
Application settings and configuration for SecureVault.
"""
import os
from pathlib import Path

# Application info
APP_NAME = "SecureVault"
APP_VERSION = "1.0.0"
ORGANIZATION_NAME = "SecureVault"
ORGANIZATION_DOMAIN = "securevault.example.com"

# Default paths
BASE_DIR = Path(__file__).parent.parent
ASSETS_DIR = BASE_DIR / 'assets'
ICON_PATH = str(ASSETS_DIR / 'icon.png')

# Ensure assets directory exists
os.makedirs(ASSETS_DIR, exist_ok=True)

# Default settings
DEFAULT_SETTINGS = {
    'app': {
        'theme': 'dark',  # 'dark' or 'light'
        'language': 'en',
        'check_for_updates': True,
        'auto_lock': 15,  # minutes, 0 to disable
        'clear_clipboard': True,
        'clipboard_clear_time': 30,  # seconds
    },
    'window': {
        'width': 1000,
        'height': 700,
        'maximized': False,
        'pos_x': None,
        'pos_y': None,
    },
    'recent_files': [],
    'key_storage': {
        'location': 'local',  # 'local' or 'cloud'
        'auto_backup': True,
        'backup_location': str(Path.home() / 'SecureVault_Backups'),
    },
}

# Encryption settings
ENCRYPTION = {
    'algorithm': 'AES-256-GCM',
    'key_derivation_iterations': 100000,
    'salt_length': 32,  # bytes
    'iv_length': 12,    # bytes for GCM
    'tag_length': 16,   # bytes
    'chunk_size': 64 * 1024,  # 64KB chunks for large files
}

# UI settings
UI = {
    'button': {
        'min_width': 200,
        'min_height': 40,
        'padding': (12, 24, 12, 24),  # top, right, bottom, left
    },
    'font': {
        'family': 'Segoe UI, Roboto, Arial, sans-serif',
        'size': 12,
        'title_size': 32,
        'subtitle_size': 14,
    },
}

def get_settings():
    """Get application settings."""
    # TODO: Load settings from persistent storage
    return DEFAULT_SETTINGS.copy()

def save_settings(settings):
    """Save application settings."""
    # TODO: Save settings to persistent storage
    pass
