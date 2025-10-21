"""
Helper functions for SecureVault Linux GUI
"""
import os
import sys
from pathlib import Path
from typing import Optional, Tuple

from PyQt6.QtWidgets import (
    QFileDialog, QMessageBox, QWidget, QApplication
)
from PyQt6.QtCore import QStandardPaths, QSize, Qt
from PyQt6.QtGui import QIcon, QPixmap, QColor

def get_icon(name: str) -> Optional[QIcon]:
    """
    Get an icon from the resources directory
    
    Args:
        name: Icon name without extension (assumes .png)
        
    Returns:
        QIcon if found, None otherwise
    """
    icon_path = Path(__file__).parent.parent / "resources" / f"{name}.png"
    if icon_path.exists():
        return QIcon(str(icon_path))
    return None

def get_save_file(
    parent: QWidget,
    title: str,
    file_filter: str = "All Files (*)",
    default_dir: str = "",
    default_name: str = ""
) -> Optional[str]:
    """Show file save dialog and return selected path"""
    if not default_dir:
        default_dir = str(Path.home())
    
    path, _ = QFileDialog.getSaveFileName(
        parent,
        title,
        os.path.join(default_dir, default_name),
        file_filter
    )
    return path if path else None

def get_open_file(
    parent: QWidget,
    title: str,
    file_filter: str = "All Files (*)",
    default_dir: str = ""
) -> Optional[str]:
    """Show file open dialog and return selected path"""
    if not default_dir:
        default_dir = str(Path.home())
    
    path, _ = QFileDialog.getOpenFileName(
        parent,
        title,
        default_dir,
        file_filter
    )
    return path if path else None

def show_error(
    parent: QWidget,
    title: str,
    message: str,
    details: str = ""
) -> None:
    """Show error message dialog"""
    msg = QMessageBox(parent)
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setWindowTitle(title)
    msg.setText(message)
    
    if details:
        msg.setDetailedText(details)
    
    msg.exec()

def show_info(
    parent: QWidget,
    title: str,
    message: str
) -> None:
    """Show information message dialog"""
    QMessageBox.information(parent, title, message)

def show_question(
    parent: QWidget,
    title: str,
    question: str,
    default_button: QMessageBox.StandardButton = QMessageBox.StandardButton.Yes
) -> QMessageBox.StandardButton:
    """Show question dialog and return user's choice"""
    return QMessageBox.question(
        parent,
        title,
        question,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        default_button
    )

def get_screen_geometry() -> Tuple[int, int, int, int]:
    """Get the available screen geometry (x, y, width, height)"""
    app = QApplication.instance()
    if not app:
        return (0, 0, 1024, 768)
    
    screen = app.primaryScreen()
    if not screen:
        return (0, 0, 1024, 768)
    
    geometry = screen.availableGeometry()
    return (
        geometry.x(),
        geometry.y(),
        geometry.width(),
        geometry.height()
    )

def center_window(window: QWidget) -> None:
    """Center the window on the screen"""
    frame = window.frameGeometry()
    center_point = window.screen().availableGeometry().center()
    frame.moveCenter(center_point)
    window.move(frame.topLeft())

def create_pixmap(size: int, color: QColor) -> QPixmap:
    """Create a colored pixmap of the specified size"""
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(color))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(0, 0, size, size)
    painter.end()
    
    return pixmap
