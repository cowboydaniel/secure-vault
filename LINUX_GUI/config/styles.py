"""
Style sheets and themes for the SecureVault application.
"""
from PyQt6.QtCore import Qt

# Color palette
COLORS = {
    'primary': '#4a36b4',
    'primary_light': '#5a46c4',
    'primary_dark': '#3a26a4',
    'background': '#1a1a2e',
    'surface': '#16213e',
    'surface_light': '#2a3a5c',
    'text_primary': '#ffffff',
    'text_secondary': '#a0a0a0',
    'border': '#2a3a5c',
    'error': '#ff4444',
    'success': '#4CAF50',
    'warning': '#FFC107'
}

# Font settings
FONTS = {
    'base': "'Segoe UI', 'Roboto', 'Arial', sans-serif",
    'mono': "'Fira Code', 'Consolas', 'Monaco', monospace"
}

# Base style sheet
BASE_STYLE = f"""
    QMainWindow {{
        background-color: {COLORS['background']};
    }}
    
    QWidget {{
        color: {COLORS['text_primary']};
        font-family: {FONTS['base']};
    }}
    
    QPushButton {{
        background-color: {COLORS['primary']};
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 6px;
        min-width: 200px;
        font-size: 14px;
        font-weight: 500;
        margin: 8px 0;
    }}
    
    QPushButton:hover {{
        background-color: {COLORS['primary_light']};
    }}
    
    QPushButton:pressed {{
        background-color: {COLORS['primary_dark']};
        padding: 13px 24px 11px 24px;
    }}
    
    QLabel#title {{
        font-size: 32px;
        font-weight: 600;
        color: {COLORS['text_primary']};
        margin-bottom: 20px;
        letter-spacing: 1px;
    }}
    
    QLabel#subtitle {{
        font-size: 14px;
        color: {COLORS['text_secondary']};
        margin-bottom: 30px;
    }}
    
    QWidget#menu_frame {{
        background-color: {COLORS['surface']};
        border-radius: 12px;
        padding: 40px;
        border: 1px solid {COLORS['border']};
    }}
    
    /* Header styles */
    #header {{
        background-color: {COLORS['background']};
        border-bottom: 1px solid {COLORS['border']};
    }}
    
    #app_title {{
        font-size: 18px;
        font-weight: 600;
        color: {COLORS['text_primary']};
    }}
    
    #logo {{
        color: white;
        background-color: {COLORS['primary']};
        border-radius: 4px;
        text-align: center;
        font-weight: bold;
        font-size: 14px;
        line-height: 32px;
    }}
    
    #accountButton {{
        color: {COLORS['text_primary']};
        border: 1px solid {COLORS['border']};
        border-radius: 4px;
        padding: 4px 8px;
        background: transparent;
    }}
    
    #accountButton:hover {{
        background-color: rgba(255, 255, 255, 0.1);
    }}
    
    #accountButton::menu-indicator {{ image: none; }}
    
    /* Footer styles */
    #footer {{
        background-color: {COLORS['background']};
        border-top: 1px solid {COLORS['border']};
    }}
    
    #statusLabel, #versionLabel {{
        color: {COLORS['text_secondary']};
        font-size: 12px;
    }}
"""

# Additional style components
STYLES = {
    'error': f"color: {COLORS['error']}; font-weight: bold;",
    'success': f"color: {COLORS['success']};",
    'warning': f"color: {COLORS['warning']};"
}

def apply_style(widget, style_name):
    """Apply a named style to a widget."""
    if style_name in STYLES:
        widget.setStyleSheet(STYLES[style_name])
    return widget
