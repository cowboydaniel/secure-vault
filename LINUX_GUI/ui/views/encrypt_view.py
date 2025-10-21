"""
Encryption view for the SecureVault application.
"""
import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QFileDialog, QProgressBar, QTextEdit, QGroupBox, QCheckBox, QSpinBox,
    QComboBox, QFormLayout
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread, pyqtSlot
from PyQt6.QtGui import QDragEnterEvent, QDropEvent

# Add parent directory to path for imports
project_root = str(Path(__file__).parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from LINUX_GUI.widgets.secure_password_input import SecurePasswordInput
from LINUX_GUI.widgets.file_drop_zone import FileDropZone


class EncryptionWorker(QThread):
    """Worker thread for encryption operations."""

    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # success, message

    def __init__(self, files, output_dir, password, options):
        super().__init__()
        self.files = files
        self.output_dir = output_dir
        self.password = password
        self.options = options
        self._is_running = True

    def run(self):
        """Run the encryption process."""
        try:
            # Import here to avoid circular imports
            from pipeline import EncryptionPipeline
            from config import PipelineConfig

            total_files = len(self.files)

            for idx, file_path in enumerate(self.files):
                if not self._is_running:
                    self.finished.emit(False, "Operation cancelled")
                    return

                self.status.emit(f"Encrypting {Path(file_path).name}...")

                # Configure pipeline
                config = PipelineConfig()
                config.use_compression = self.options.get('compression', True)
                config.compression_algorithm = self.options.get('compression_algo', 'zstd')

                # Create pipeline
                pipeline = EncryptionPipeline(config)

                # Encrypt file
                output_path = Path(self.output_dir) / f"{Path(file_path).name}.encrypted"

                try:
                    pipeline.encrypt_file(
                        input_file=file_path,
                        output_file=str(output_path),
                        passphrase=self.password
                    )

                    # Update progress
                    progress_percent = int(((idx + 1) / total_files) * 100)
                    self.progress.emit(progress_percent)

                except Exception as e:
                    self.finished.emit(False, f"Error encrypting {Path(file_path).name}: {str(e)}")
                    return

            self.finished.emit(True, f"Successfully encrypted {total_files} file(s)")

        except Exception as e:
            self.finished.emit(False, f"Encryption error: {str(e)}")

    def stop(self):
        """Stop the encryption process."""
        self._is_running = False


class EncryptView(QWidget):
    """View for encrypting files."""

    back_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.files_to_encrypt = []
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 20, 40, 20)

        # Title
        title = QLabel("Encrypt Files")
        title.setObjectName("title")
        title.setStyleSheet("font-size: 24px; font-weight: 600; margin-bottom: 20px;")

        # File selection group
        file_group = QGroupBox("Select Files")
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
        password_group = QGroupBox("Encryption Settings")
        password_layout = QFormLayout(password_group)

        # Password input
        self.password_input = SecurePasswordInput()
        password_layout.addRow("Password:", self.password_input)

        # Confirm password
        self.password_confirm = SecurePasswordInput()
        password_layout.addRow("Confirm:", self.password_confirm)

        # Compression settings
        self.compression_check = QCheckBox("Enable compression")
        self.compression_check.setChecked(True)
        password_layout.addRow(self.compression_check)

        self.compression_combo = QComboBox()
        self.compression_combo.addItems(['zstd', 'lz4', 'zlib'])
        self.compression_combo.setEnabled(True)
        password_layout.addRow("Algorithm:", self.compression_combo)

        self.compression_check.toggled.connect(self.compression_combo.setEnabled)

        # Output directory
        output_layout = QHBoxLayout()
        self.output_dir = QLineEdit()
        self.output_dir.setPlaceholderText("Select output directory...")
        self.output_dir.setText(str(Path.home() / "SecureVault_Encrypted"))
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

        self.btn_encrypt = QPushButton("Encrypt")
        self.btn_encrypt.setEnabled(False)
        self.btn_encrypt.clicked.connect(self.start_encryption)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel_encryption)

        button_layout.addWidget(self.btn_back)
        button_layout.addWidget(self.btn_cancel)
        button_layout.addWidget(self.btn_encrypt)

        # Add all groups to main layout
        layout.addWidget(title)
        layout.addWidget(file_group)
        layout.addWidget(password_group)
        layout.addWidget(progress_group)
        layout.addLayout(button_layout)
        layout.addStretch()

        # Connect signals
        self.password_input.textChanged.connect(self.check_ready)
        self.password_confirm.textChanged.connect(self.check_ready)

    def browse_files(self):
        """Open file browser to select files."""
        files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select Files to Encrypt",
            str(Path.home()),
            "All Files (*.*)"
        )

        if files:
            self.on_files_dropped(files)

    def browse_output_dir(self):
        """Browse for output directory."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            str(Path.home())
        )

        if directory:
            self.output_dir.setText(directory)

    def on_files_dropped(self, files):
        """Handle dropped files."""
        self.files_to_encrypt.extend(files)
        # Remove duplicates
        self.files_to_encrypt = list(set(self.files_to_encrypt))

        # Update file list display
        file_names = [Path(f).name for f in self.files_to_encrypt]
        self.file_list.setText('\n'.join(file_names))

        self.check_ready()

    def check_ready(self):
        """Check if ready to encrypt."""
        has_files = len(self.files_to_encrypt) > 0
        has_password = len(self.password_input.text()) > 0
        passwords_match = self.password_input.text() == self.password_confirm.text()

        self.btn_encrypt.setEnabled(has_files and has_password and passwords_match)

        # Update status
        if has_password and not passwords_match:
            self.status_label.setText("Passwords do not match")
            self.status_label.setStyleSheet("color: #ff4444;")
        else:
            self.status_label.setText("Ready")
            self.status_label.setStyleSheet("color: #4CAF50;")

    def start_encryption(self):
        """Start the encryption process."""
        # Validate output directory
        output_dir = Path(self.output_dir.text())
        output_dir.mkdir(parents=True, exist_ok=True)

        # Prepare options
        options = {
            'compression': self.compression_check.isChecked(),
            'compression_algo': self.compression_combo.currentText(),
        }

        # Create and start worker
        self.worker = EncryptionWorker(
            self.files_to_encrypt,
            str(output_dir),
            self.password_input.text(),
            options
        )

        self.worker.progress.connect(self.update_progress)
        self.worker.status.connect(self.update_status)
        self.worker.finished.connect(self.encryption_finished)

        # Update UI
        self.btn_encrypt.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_browse.setEnabled(False)
        self.password_input.setEnabled(False)
        self.password_confirm.setEnabled(False)

        self.worker.start()

    def cancel_encryption(self):
        """Cancel the encryption process."""
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
    def encryption_finished(self, success, message):
        """Handle encryption completion."""
        self.update_status(message)

        if success:
            self.status_label.setStyleSheet("color: #4CAF50;")
            self.progress_bar.setValue(100)
            # Clear files after successful encryption
            self.files_to_encrypt.clear()
            self.file_list.clear()
        else:
            self.status_label.setStyleSheet("color: #ff4444;")

        self.reset_ui()

    def reset_ui(self):
        """Reset UI to initial state."""
        self.btn_encrypt.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_browse.setEnabled(True)
        self.password_input.setEnabled(True)
        self.password_confirm.setEnabled(True)
        self.password_input.clear()
        self.password_confirm.clear()
        self.check_ready()
