"""
Theme management for SecureVault application.
Supports light and dark themes.
"""

# Dark theme colors
DARK_COLORS = {
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

# Light theme colors
LIGHT_COLORS = {
    'primary': '#4a36b4',
    'primary_light': '#5a46c4',
    'primary_dark': '#3a26a4',
    'background': '#f5f5f5',
    'surface': '#ffffff',
    'surface_light': '#e0e0e0',
    'text_primary': '#212121',
    'text_secondary': '#666666',
    'border': '#cccccc',
    'error': '#d32f2f',
    'success': '#388e3c',
    'warning': '#f57c00'
}

# Font settings (same for both themes)
FONTS = {
    'base': "'Segoe UI', 'Roboto', 'Arial', sans-serif",
    'mono': "'Fira Code', 'Consolas', 'Monaco', monospace"
}


def get_stylesheet(theme='dark'):
    """Get the stylesheet for the specified theme.

    Args:
        theme: Theme name ('dark' or 'light')

    Returns:
        str: CSS stylesheet
    """
    colors = DARK_COLORS if theme == 'dark' else LIGHT_COLORS

    return f"""
    QMainWindow {{
        background-color: {colors['background']};
    }}

    QWidget {{
        color: {colors['text_primary']};
        font-family: {FONTS['base']};
    }}

    QPushButton {{
        background-color: {colors['primary']};
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
        background-color: {colors['primary_light']};
    }}

    QPushButton:pressed {{
        background-color: {colors['primary_dark']};
        padding: 13px 24px 11px 24px;
    }}

    QPushButton:disabled {{
        background-color: {colors['border']};
        color: {colors['text_secondary']};
    }}

    QLineEdit {{
        background-color: {colors['surface']};
        color: {colors['text_primary']};
        border: 1px solid {colors['border']};
        border-radius: 4px;
        padding: 8px;
        font-size: 14px;
    }}

    QLineEdit:focus {{
        border: 1px solid {colors['primary']};
    }}

    QTextEdit {{
        background-color: {colors['surface']};
        color: {colors['text_primary']};
        border: 1px solid {colors['border']};
        border-radius: 4px;
        padding: 8px;
    }}

    QComboBox {{
        background-color: {colors['surface']};
        color: {colors['text_primary']};
        border: 1px solid {colors['border']};
        border-radius: 4px;
        padding: 6px;
    }}

    QComboBox::drop-down {{
        border: none;
        width: 20px;
    }}

    QComboBox QAbstractItemView {{
        background-color: {colors['surface']};
        color: {colors['text_primary']};
        selection-background-color: {colors['primary']};
        border: 1px solid {colors['border']};
    }}

    QCheckBox {{
        color: {colors['text_primary']};
    }}

    QCheckBox::indicator {{
        width: 18px;
        height: 18px;
        border: 2px solid {colors['border']};
        border-radius: 3px;
        background-color: {colors['surface']};
    }}

    QCheckBox::indicator:checked {{
        background-color: {colors['primary']};
        border-color: {colors['primary']};
    }}

    QGroupBox {{
        color: {colors['text_primary']};
        border: 1px solid {colors['border']};
        border-radius: 6px;
        margin-top: 12px;
        padding-top: 12px;
        font-weight: 500;
    }}

    QGroupBox::title {{
        subcontrol-origin: margin;
        left: 10px;
        padding: 0 5px;
    }}

    QTableWidget {{
        background-color: {colors['surface']};
        color: {colors['text_primary']};
        alternate-background-color: {colors['surface_light']};
        border: 1px solid {colors['border']};
        gridline-color: {colors['border']};
    }}

    QTableWidget::item:selected {{
        background-color: {colors['primary']};
        color: white;
    }}

    QHeaderView::section {{
        background-color: {colors['surface_light']};
        color: {colors['text_primary']};
        padding: 6px;
        border: none;
        border-bottom: 1px solid {colors['border']};
        font-weight: 600;
    }}

    QProgressBar {{
        border: 1px solid {colors['border']};
        border-radius: 4px;
        text-align: center;
        background-color: {colors['surface']};
        color: {colors['text_primary']};
    }}

    QProgressBar::chunk {{
        background-color: {colors['primary']};
        border-radius: 3px;
    }}

    QMenuBar {{
        background-color: {colors['background']};
        color: {colors['text_primary']};
    }}

    QMenuBar::item:selected {{
        background-color: {colors['surface_light']};
    }}

    QMenu {{
        background-color: {colors['surface']};
        color: {colors['text_primary']};
        border: 1px solid {colors['border']};
    }}

    QMenu::item:selected {{
        background-color: {colors['primary']};
        color: white;
    }}

    QLabel#title {{
        font-size: 32px;
        font-weight: 600;
        color: {colors['text_primary']};
        margin-bottom: 20px;
        letter-spacing: 1px;
    }}

    QLabel#subtitle {{
        font-size: 14px;
        color: {colors['text_secondary']};
        margin-bottom: 30px;
    }}

    /* Header styles */
    #header {{
        background-color: {colors['background']};
        border-bottom: 1px solid {colors['border']};
    }}

    #app_title {{
        font-size: 18px;
        font-weight: 600;
        color: {colors['text_primary']};
    }}

    #logo {{
        color: white;
        background-color: {colors['primary']};
        border-radius: 4px;
        text-align: center;
        font-weight: bold;
        font-size: 14px;
        line-height: 32px;
    }}

    #accountButton {{
        color: {colors['text_primary']};
        border: 1px solid {colors['border']};
        border-radius: 4px;
        padding: 4px 8px;
        background: transparent;
    }}

    #accountButton:hover {{
        background-color: {colors['surface_light']};
    }}

    #accountButton::menu-indicator {{ image: none; }}

    /* Footer styles */
    #footer {{
        background-color: {colors['background']};
        border-top: 1px solid {colors['border']};
    }}

    #statusLabel, #versionLabel {{
        color: {colors['text_secondary']};
        font-size: 12px;
    }}

    QDialog {{
        background-color: {colors['background']};
    }}

    QDialogButtonBox QPushButton {{
        min-width: 80px;
    }}
    """


class ThemeManager:
    """Manager for application themes."""

    def __init__(self):
        self.current_theme = 'dark'

    def get_theme(self):
        """Get the current theme name."""
        return self.current_theme

    def set_theme(self, theme):
        """Set the current theme.

        Args:
            theme: Theme name ('dark' or 'light')
        """
        if theme in ['dark', 'light']:
            self.current_theme = theme

    def get_stylesheet(self):
        """Get the stylesheet for the current theme."""
        return get_stylesheet(self.current_theme)
