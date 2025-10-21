"""
File drop zone widget for drag-and-drop file selection.
"""
from PyQt6.QtWidgets import QLabel, QWidget, QVBoxLayout
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent


class FileDropZone(QWidget):
    """Widget that accepts drag-and-drop file uploads."""

    files_dropped = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setup_ui()

    def setup_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)

        self.label = QLabel("Drag and drop files here\nor click Browse")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("""
            QLabel {
                border: 2px dashed #4a36b4;
                border-radius: 8px;
                padding: 40px;
                background-color: rgba(74, 54, 180, 0.1);
                color: #a0a0a0;
                font-size: 14px;
            }
        """)
        self.label.setMinimumHeight(120)

        layout.addWidget(self.label)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Handle drag enter events."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            self.label.setStyleSheet("""
                QLabel {
                    border: 2px dashed #5a46c4;
                    border-radius: 8px;
                    padding: 40px;
                    background-color: rgba(74, 54, 180, 0.2);
                    color: #ffffff;
                    font-size: 14px;
                }
            """)

    def dragLeaveEvent(self, event):
        """Handle drag leave events."""
        self.label.setStyleSheet("""
            QLabel {
                border: 2px dashed #4a36b4;
                border-radius: 8px;
                padding: 40px;
                background-color: rgba(74, 54, 180, 0.1);
                color: #a0a0a0;
                font-size: 14px;
            }
        """)

    def dropEvent(self, event: QDropEvent):
        """Handle drop events."""
        files = []
        for url in event.mimeData().urls():
            file_path = url.toLocalFile()
            if file_path:
                files.append(file_path)

        if files:
            self.files_dropped.emit(files)

        # Reset styling
        self.label.setStyleSheet("""
            QLabel {
                border: 2px dashed #4a36b4;
                border-radius: 8px;
                padding: 40px;
                background-color: rgba(74, 54, 180, 0.1);
                color: #a0a0a0;
                font-size: 14px;
            }
        """)

        event.acceptProposedAction()
