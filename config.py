"""
Configuration settings for SecureVault Linux GUI
"""
import os
from pathlib import Path

# Application info
APP_NAME = "SecureVault"
APP_VERSION = "1.0.0"
ORGANIZATION_NAME = "SecureVault"
ORGANIZATION_DOMAIN = "securevault.app"

# Paths
BASE_DIR = Path(__file__).parent
UI_DIR = BASE_DIR / "ui"
RESOURCES_DIR = BASE_DIR / "resources"
STYLES_DIR = BASE_DIR / "styles"

# Create necessary directories
for directory in [UI_DIR, RESOURCES_DIR, STYLES_DIR]:
    directory.mkdir(exist_ok=True)

# Application settings
DEFAULT_WINDOW_WIDTH = 1024
DEFAULT_WINDOW_HEIGHT = 768
MIN_WINDOW_WIDTH = 800
MIN_WINDOW_HEIGHT = 600

# Theme settings
DARK_THEME = {
    "primary": "#4a86e8",
    "primary_light": "#7aa7e8",
    "primary_dark": "#1a56d8",
    "background": "#1e1e1e",
    "surface": "#2d2d2d",
    "text_primary": "#ffffff",
    "text_secondary": "#b0b0b0",
    "error": "#f44336",
    "success": "#4caf50",
    "warning": "#ff9800"
}

LIGHT_THEME = {
    "primary": "#4a86e8",
    "primary_light": "#7aa7e8",
    "primary_dark": "#1a56d8",
    "background": "#f5f5f5",
    "surface": "#ffffff",
    "text_primary": "#000000",
    "text_secondary": "#666666",
    "error": "#d32f2f",
    "success": "#388e3c",
    "warning": "#f57c00"
}

# Default theme
THEME = LIGHT_THEME

# Application settings
class Settings:
    """Application settings manager"""
    def __init__(self):
        self.theme = "light"  # 'light' or 'dark'
        self.window_geometry = None
        self.recent_files = []
        self.default_save_dir = str(Path.home() / "SecureVault")
        
        # Create default save directory if it doesn't exist
        os.makedirs(self.default_save_dir, exist_ok=True)
    
    def get_theme(self):
        """Get current theme colors"""
        return DARK_THEME if self.theme == "dark" else LIGHT_THEME

# Global settings instance
settings = Settings()
