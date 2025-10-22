#!/usr/bin/env python3
"""
Test script for SecureVault GUI.
Run this to verify the GUI is working correctly.
"""
import os
import sys
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

REQUIRED_BUTTONS = {
    "Encrypt File",
    "Decrypt File",
    "Key Manager",
    "Secure Notes",
    "Activity Monitor",
    "Vault Health Check",
}


def main() -> int:
    """Smoke-test the SecureVault GUI without requiring a display server."""

    # Allow the GUI to run in CI/headless environments.
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    try:
        from PyQt6.QtWidgets import QApplication, QPushButton
        from PyQt6.QtCore import Qt, QTimer

        from LINUX_GUI.ui.main_window import MainWindow
    except ImportError as exc:
        print(f"Error: Missing dependency - {exc}")
        if "libGL" in str(exc):
            print("The host system is missing libGL. Install mesa-libGL or an equivalent package.")
        else:
            print("Please install PyQt6: pip install PyQt6")
        return 1

    class DummyAuthManager:
        """Minimal stub used for GUI validation."""

        def logout(self, *_args, **_kwargs):  # pragma: no cover - defensive stub
            pass

    try:
        print("Starting SecureVault GUI test...")

        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )

        app = QApplication(sys.argv)
        app.setStyle("Fusion")
        app.setApplicationName("SecureVault")
        app.setApplicationVersion("1.0.0")

        window = MainWindow(auth_manager=DummyAuthManager())
        window.show()

        def verify_buttons() -> None:
            discovered = {
                btn.text().strip()
                for btn in window.findChildren(QPushButton)
                if btn.isVisible()
            }

            print("Discovered main menu buttons:", ", ".join(sorted(discovered)))

            missing = REQUIRED_BUTTONS - discovered
            if missing:
                print("Missing buttons:", ", ".join(sorted(missing)))
                app.exit(1)
            else:
                print("All expected feature buttons are present.")
                app.exit(0)

        QTimer.singleShot(100, verify_buttons)

        return app.exec()

    except Exception as exc:  # pragma: no cover - diagnostic output for manual runs
        print(f"Error starting GUI: {exc}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
