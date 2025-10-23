"""
Decryption view for the SecureVault application.
"""
import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QProgressBar, QTextEdit, QGroupBox, QFormLayout, QMessageBox
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, pyqtSlot

# Add parent directory to path for imports
project_root = str(Path(__file__).parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from LINUX_GUI.widgets.secure_password_input import SecurePasswordInput
from LINUX_GUI.widgets.file_drop_zone import FileDropZone
from file_utils import validate_storage_path


class DecryptionWorker(QThread):
    """Worker thread for decryption operations."""

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # success, message

    def __init__(self, files, output_dir, password):
        super().__init__()
        self.files = files
        self.output_dir = output_dir
        self.password = password
        self._is_running = True

    def run(self):
        """Run the decryption process."""
        try:
            # Import here to avoid circular imports
            from pipeline import EncryptionPipeline
            from config import PipelineConfig

            total_files = len(self.files)

            for idx, file_path in enumerate(self.files):
                if not self._is_running:
                    self.finished.emit(False, "Operation cancelled")
                    return

                self.status.emit(f"Decrypting {Path(file_path).name}...")

                # Create pipeline
                config = PipelineConfig()
                pipeline = EncryptionPipeline(config)

                # Decrypt file
                file_name = Path(file_path).stem  # Remove .encrypted extension
                output_path = Path(self.output_dir) / file_name

                try:
                    pipeline.decrypt_file(
                        input_file=file_path,
                        output_file=str(output_path),
                        passphrase=self.password
                    )

                    # Update progress
                    progress_percent = int(((idx + 1) / total_files) * 100)
                    self.progress.emit(progress_percent)

                except Exception as e:
                    self.finished.emit(False, f"Error decrypting {Path(file_path).name}: {str(e)}")
                    return

            self.finished.emit(True, f"Successfully decrypted {total_files} file(s)")

        except Exception as e:
            self.finished.emit(False, f"Decryption error: {str(e)}")

    def stop(self):
        """Stop the decryption process."""
        self._is_running = False


class DecryptView(QWidget):
    """View for decrypting files."""

    back_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.files_to_decrypt = []
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 20, 40, 20)

        # Title
        title = QLabel("Decrypt Files")
        title.setObjectName("title")
        title.setStyleSheet("font-size: 24px; font-weight: 600; margin-bottom: 20px;")

        # File selection group
        file_group = QGroupBox("Select Encrypted Files")
        file_layout = QVBoxLayout(file_group)

        # Drop zone
        self.drop_zone = FileDropZone()
        self.drop_zone.files_dropped.connect(self.on_files_dropped)
        file_layout.addWidget(self.drop_zone)

        # Browse button
        btn_layout = QHBoxLayout()
        self.btn_browse = QPushButton("Browse Files...")
        self.btn_browse.clicked.connect(self.browse_files)
        btn_layout.addWidget(self.btn_browse)
        btn_layout.addStretch()
        file_layout.addLayout(btn_layout)

        # Selected files list
        self.file_list = QTextEdit()
        self.file_list.setReadOnly(True)
        self.file_list.setMaximumHeight(100)
        self.file_list.setPlaceholderText("No files selected")
        file_layout.addWidget(QLabel("Selected files:"))
        file_layout.addWidget(self.file_list)

        # Password group
        password_group = QGroupBox("Decryption Settings")
        password_layout = QFormLayout(password_group)

        # Password input
        self.password_input = SecurePasswordInput()
        password_layout.addRow("Password:", self.password_input)

        # Output directory
        output_layout = QHBoxLayout()
        self.output_dir = QLineEdit()
        self.output_dir.setPlaceholderText("Select output directory...")
        try:
            default_output = validate_storage_path(None)
        except ValueError:
            default_output = Path.home()
        self.output_dir.setText(str(default_output))
        btn_output = QPushButton("Browse...")
        btn_output.clicked.connect(self.browse_output_dir)
        output_layout.addWidget(self.output_dir)
        output_layout.addWidget(btn_output)
        password_layout.addRow("Output:", output_layout)

        # Progress group
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #a0a0a0; font-size: 12px;")
        progress_layout.addWidget(self.status_label)

        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.btn_back = QPushButton("Back")
        self.btn_back.clicked.connect(self.back_requested.emit)

        self.btn_decrypt = QPushButton("Decrypt")
        self.btn_decrypt.setEnabled(False)
        self.btn_decrypt.clicked.connect(self.start_decryption)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_decryption)

        button_layout.addWidget(self.btn_back)
        button_layout.addWidget(self.btn_cancel)
        button_layout.addWidget(self.btn_decrypt)

        # Add all groups to main layout
        layout.addWidget(title)
        layout.addWidget(file_group)
        layout.addWidget(password_group)
        layout.addWidget(progress_group)
        layout.addLayout(button_layout)
        layout.addStretch()

        # Connect signals
        self.password_input.textChanged.connect(self.check_ready)

    def browse_files(self):
        """Open file browser to select encrypted files."""
        try:
            start_dir = str(validate_storage_path(None))
        except ValueError:
            start_dir = str(Path.home())

        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Encrypted Files",
            start_dir,
            "Encrypted Files (*.encrypted);;All Files (*.*)"
        )

        if files:
            self.on_files_dropped(files)

    def browse_output_dir(self):
        """Browse for output directory."""
        try:
            start_dir = str(validate_storage_path(None))
        except ValueError:
            start_dir = str(Path.home())

        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            start_dir
        )

        if directory:
            try:
                validated = validate_storage_path(directory)
            except ValueError as exc:
                QMessageBox.critical(self, "Invalid directory", str(exc))
                return
            self.output_dir.setText(str(validated))

    def on_files_dropped(self, files):
        """Handle dropped files."""
        self.files_to_decrypt.extend(files)
        # Remove duplicates
        self.files_to_decrypt = list(set(self.files_to_decrypt))

        # Update file list display
        file_names = [Path(f).name for f in self.files_to_decrypt]
        self.file_list.setText('\n'.join(file_names))

        self.check_ready()

    def check_ready(self):
        """Check if ready to decrypt."""
        has_files = len(self.files_to_decrypt) > 0
        has_password = len(self.password_input.text()) > 0

        self.btn_decrypt.setEnabled(has_files and has_password)

        # Update status
        if has_files and has_password:
            self.status_label.setText("Ready")
            self.status_label.setStyleSheet("color: #4CAF50;")
        else:
            self.status_label.setText("Select files and enter password")
            self.status_label.setStyleSheet("color: #a0a0a0;")

    def start_decryption(self):
        """Start the decryption process."""
        # Validate output directory
        try:
            output_dir = validate_storage_path(self.output_dir.text().strip() or None, create=True)
        except ValueError as exc:
            QMessageBox.critical(self, "Invalid output directory", str(exc))
            self.update_status("Invalid output directory")
            return

        # Create and start worker
        self.worker = DecryptionWorker(
            self.files_to_decrypt,
            str(output_dir),
            self.password_input.text()
        )

        self.worker.progress.connect(self.update_progress)
        self.worker.status.connect(self.update_status)
        self.worker.finished.connect(self.decryption_finished)

        # Update UI
        self.btn_decrypt.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_browse.setEnabled(False)
        self.password_input.setEnabled(False)

        self.worker.start()

    def cancel_decryption(self):
        """Cancel the decryption process."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            self.update_status("Cancelled")
            self.reset_ui()

    @pyqtSlot(int)
    def update_progress(self, value):
        """Update progress bar."""
        self.progress_bar.setValue(value)

    @pyqtSlot(str)
    def update_status(self, message):
        """Update status label."""
        self.status_label.setText(message)

    @pyqtSlot(bool, str)
    def decryption_finished(self, success, message):
        """Handle decryption completion."""
        self.update_status(message)

        if success:
            self.status_label.setStyleSheet("color: #4CAF50;")
            self.progress_bar.setValue(100)
            # Clear files after successful decryption
            self.files_to_decrypt.clear()
            self.file_list.clear()
        else:
            self.status_label.setStyleSheet("color: #ff4444;")

        self.reset_ui()

    def reset_ui(self):
        """Reset UI to initial state."""
        self.btn_decrypt.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_browse.setEnabled(True)
        self.password_input.setEnabled(True)
        self.password_input.clear()
        self.check_ready()
