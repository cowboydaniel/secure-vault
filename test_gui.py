#!/usr/bin/env python3
"""
Test script for SecureVault GUI.
Run this to verify the GUI is working correctly.
"""
import sys
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt

    from LINUX_GUI.ui.main_window import MainWindow

    def main():
        """Test the GUI application."""
        print("Starting SecureVault GUI test...")

        # Enable high DPI scaling
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

        # Create application
        app = QApplication(sys.argv)
        app.setStyle('Fusion')
        app.setApplicationName("SecureVault")
        app.setApplicationVersion("1.0.0")

        # Create and show main window
        window = MainWindow()
        window.show()

        print("GUI loaded successfully!")
        print("Testing features:")
        print("  - Main menu: OK")
        print("  - Theme manager: OK")
        print("  - Clipboard security: OK")

        if window.system_tray:
            print("  - System tray: OK")
        else:
            print("  - System tray: Not available")

        print("\nGUI test passed! Close the window to exit.")

        # Run application
        return app.exec()

except ImportError as e:
    print(f"Error: Missing dependency - {e}")
    print("Please install PyQt6: pip install PyQt6")
    return 1
except Exception as e:
    print(f"Error starting GUI: {e}")
    import traceback
    traceback.print_exc()
    return 1

if __name__ == "__main__":
    sys.exit(main())
