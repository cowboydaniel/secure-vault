#!/usr/bin/env python3
"""SecureVault Linux GUI entry point with authentication enforcement."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional, Tuple

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMessageBox, QDialog

# Ensure repository root is available for imports
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from audit_logger import AuditEventType, AuditSeverity, AuditLogger, get_audit_logger  # noqa: E402
from auth_manager import AuthManager, AuthSession, SystemLockdownError  # noqa: E402
from auth_manager import AuthManager, AuthSession  # noqa: E402
from LINUX_GUI.ui.main_window import MainWindow  # noqa: E402
from LINUX_GUI.ui.dialogs import FirstStartWizard, LoginDialog  # noqa: E402


logger = logging.getLogger(__name__)


def _obtain_authenticated_session(
    auth_manager: AuthManager,
    audit_logger: AuditLogger,
    parent_window=None,
) -> Tuple[Optional[AuthSession], Optional[str]]:
    """Walk the operator through first-start and login flows."""

    if auth_manager.is_first_start():
        wizard = FirstStartWizard(auth_manager, audit_logger=audit_logger, parent=parent_window)
        if wizard.exec() != QDialog.DialogCode.Accepted:
            logger.info("First-start wizard cancelled; exiting GUI.")
            return None, None

    login_dialog = LoginDialog(auth_manager, audit_logger=audit_logger, parent=parent_window)
    if login_dialog.exec() != QDialog.DialogCode.Accepted:
        logger.info("Login cancelled; exiting GUI.")
        return None, None

    session = login_dialog.session
    email = login_dialog.email
    if not session or not email:
        logger.warning("Login dialog returned without session details; aborting launch.")
        return None, None

    return session, email


def main() -> int:
    """Main entry point for the Linux GUI."""

    logging.basicConfig(level=logging.INFO)

    # Ensure consistent HiDPI behaviour
    QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)

    app = QApplication(sys.argv)
    app.setApplicationName("SecureVault")
    app.setOrganizationName("SecureVault")
    app.setOrganizationDomain("securevault.local")

    # Apply project icon if available
    icon_path = Path(__file__).resolve().parent / "resources" / "icons" / "securevault.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    try:
        auth_manager = AuthManager()
    except SystemLockdownError as exc:
        QMessageBox.critical(
            None,
            "SecureVault Locked",
            (
                "SecureVault detected tampering or missing authentication data and "
                "has locked this installation.\n\n"
                f"Details: {exc}"
            ),
        )
        logger.error("Unable to start GUI due to lockdown: %s", exc)
        return 1
    auth_manager = AuthManager()
    audit_logger = get_audit_logger()

    session, email = _obtain_authenticated_session(auth_manager, audit_logger)
    if not session:
        return 0

    window: Optional[MainWindow] = None

    def handle_sign_out() -> None:
        nonlocal session, email, window

        if session:
            try:
                auth_manager.logout(session.session_id)
                audit_logger.log_event(
                    AuditEventType.AUTH_SUCCESS,
                    AuditSeverity.INFO,
                    "GUI session terminated",
                    {"session_id": session.session_id},
                    user_id=str(session.user_id),
                )
            except Exception:  # pragma: no cover - defensive logging
                logger.exception("Failed to terminate GUI session cleanly")
            finally:
                session = None
                email = None

        login_dialog = LoginDialog(auth_manager, audit_logger=audit_logger, parent=window)
        if login_dialog.exec() == QDialog.DialogCode.Accepted and login_dialog.session and login_dialog.email:
            session = login_dialog.session
            email = login_dialog.email
            if window:
                window.set_authenticated_session(session, email)
        else:
            if window:
                QMessageBox.information(
                    window,
                    "SecureVault Locked",
                    "You have been signed out of SecureVault.",
                )
                window.close()

    window = MainWindow(
        auth_manager=auth_manager,
        session=session,
        user_email=email,
        on_sign_out=handle_sign_out,
    )
    window.show()

    def cleanup() -> None:
        nonlocal session

        if session:
            try:
                auth_manager.logout(session.session_id)
                audit_logger.log_event(
                    AuditEventType.SYSTEM_SHUTDOWN,
                    AuditSeverity.INFO,
                    "GUI shutdown while authenticated",
                    {"session_id": session.session_id},
                    user_id=str(session.user_id),
                )
            except Exception:
                logger.exception("Failed to cleanly log out session during shutdown")
            finally:
                session = None

    app.aboutToQuit.connect(cleanup)

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
