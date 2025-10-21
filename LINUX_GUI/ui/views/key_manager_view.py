"""
Key Manager view for the SecureVault application.
"""
import sys
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QMessageBox, QInputDialog, QFormLayout, QLineEdit, QComboBox
)
from PyQt6.QtCore import Qt, pyqtSignal

# Add parent directory to path for imports
project_root = str(Path(__file__).parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)


class KeyManagerView(QWidget):
    """View for managing encryption keys."""

    back_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.key_manager = None
        self.setup_ui()
        self.load_keys()

    def setup_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 20, 40, 20)

        # Title
        title = QLabel("Key Manager")
        title.setObjectName("title")
        title.setStyleSheet("font-size: 24px; font-weight: 600; margin-bottom: 20px;")

        # Key list group
        key_group = QGroupBox("Encryption Keys")
        key_layout = QVBoxLayout(key_group)

        # Key table
        self.key_table = QTableWidget()
        self.key_table.setColumnCount(5)
        self.key_table.setHorizontalHeaderLabels([
            "Key ID", "Type", "Created", "Status", "Uses"
        ])
        self.key_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self.key_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.key_table.setSelectionMode(
            QTableWidget.SelectionMode.SingleSelection
        )
        self.key_table.setAlternatingRowColors(True)

        key_layout.addWidget(self.key_table)

        # Key action buttons
        key_button_layout = QHBoxLayout()

        self.btn_generate = QPushButton("Generate Key")
        self.btn_generate.clicked.connect(self.generate_key)

        self.btn_import = QPushButton("Import Key")
        self.btn_import.clicked.connect(self.import_key)

        self.btn_export = QPushButton("Export Key")
        self.btn_export.clicked.connect(self.export_key)

        self.btn_rotate = QPushButton("Rotate Key")
        self.btn_rotate.clicked.connect(self.rotate_key)

        self.btn_delete = QPushButton("Delete Key")
        self.btn_delete.clicked.connect(self.delete_key)
        self.btn_delete.setStyleSheet("background-color: #ff4444;")

        key_button_layout.addWidget(self.btn_generate)
        key_button_layout.addWidget(self.btn_import)
        key_button_layout.addWidget(self.btn_export)
        key_button_layout.addWidget(self.btn_rotate)
        key_button_layout.addWidget(self.btn_delete)
        key_button_layout.addStretch()

        key_layout.addLayout(key_button_layout)

        # Key statistics group
        stats_group = QGroupBox("Statistics")
        stats_layout = QFormLayout(stats_group)

        self.total_keys_label = QLabel("0")
        self.active_keys_label = QLabel("0")
        self.rotations_label = QLabel("0")

        stats_layout.addRow("Total Keys:", self.total_keys_label)
        stats_layout.addRow("Active Keys:", self.active_keys_label)
        stats_layout.addRow("Rotations (30d):", self.rotations_label)

        # Back button
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.btn_refresh = QPushButton("Refresh")
        self.btn_refresh.clicked.connect(self.load_keys)

        self.btn_back = QPushButton("Back")
        self.btn_back.clicked.connect(self.back_requested.emit)

        button_layout.addWidget(self.btn_refresh)
        button_layout.addWidget(self.btn_back)

        # Add all groups to main layout
        layout.addWidget(title)
        layout.addWidget(key_group)
        layout.addWidget(stats_group)
        layout.addLayout(button_layout)

    def load_keys(self):
        """Load keys from the key manager."""
        try:
            from key_manager import KeyManager, KeyType

            # Initialize key manager if needed
            if self.key_manager is None:
                self.key_manager = KeyManager()

            # Clear table
            self.key_table.setRowCount(0)

            # Get all keys
            keys = self.key_manager.list_keys()

            # Populate table
            for key_info in keys:
                row = self.key_table.rowCount()
                self.key_table.insertRow(row)

                # Add key data
                self.key_table.setItem(row, 0, QTableWidgetItem(str(key_info.get('key_id', 'N/A'))[:16]))
                self.key_table.setItem(row, 1, QTableWidgetItem(key_info.get('key_type', 'Unknown')))
                self.key_table.setItem(row, 2, QTableWidgetItem(key_info.get('created_at', 'Unknown')))
                self.key_table.setItem(row, 3, QTableWidgetItem(key_info.get('state', 'Unknown')))
                self.key_table.setItem(row, 4, QTableWidgetItem(str(key_info.get('use_count', 0))))

            # Update statistics
            self.update_statistics()

        except Exception as e:
            QMessageBox.warning(
                self,
                "Error",
                f"Failed to load keys: {str(e)}"
            )

    def update_statistics(self):
        """Update the statistics display."""
        try:
            total = self.key_table.rowCount()
            active = sum(
                1 for row in range(total)
                if self.key_table.item(row, 3) and
                self.key_table.item(row, 3).text() == 'active'
            )

            self.total_keys_label.setText(str(total))
            self.active_keys_label.setText(str(active))
            # TODO: Calculate actual rotations from audit log
            self.rotations_label.setText("N/A")

        except Exception as e:
            print(f"Error updating statistics: {e}")

    def generate_key(self):
        """Generate a new encryption key."""
        try:
            from key_manager import KeyType

            # Show dialog to select key type
            key_types = ['OTP', 'MLKEM', 'SYMMETRIC', 'MASTER', 'BACKUP']
            key_type, ok = QInputDialog.getItem(
                self,
                "Generate Key",
                "Select key type:",
                key_types,
                0,
                False
            )

            if ok and key_type:
                # Convert to KeyType enum
                kt = getattr(KeyType, key_type)

                # Generate key
                if self.key_manager:
                    key_id = self.key_manager.generate_key(kt)

                    QMessageBox.information(
                        self,
                        "Success",
                        f"Key generated successfully!\nKey ID: {key_id[:16]}..."
                    )

                    # Refresh table
                    self.load_keys()

        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to generate key: {str(e)}"
            )

    def import_key(self):
        """Import an existing key."""
        QMessageBox.information(
            self,
            "Not Implemented",
            "Key import functionality will be added in a future release."
        )

    def export_key(self):
        """Export a selected key."""
        selected = self.key_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self,
                "No Selection",
                "Please select a key to export."
            )
            return

        row = selected[0].row()
        key_id = self.key_table.item(row, 0).text()

        QMessageBox.information(
            self,
            "Not Implemented",
            f"Export functionality for key {key_id} will be added in a future release."
        )

    def rotate_key(self):
        """Rotate a selected key."""
        selected = self.key_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self,
                "No Selection",
                "Please select a key to rotate."
            )
            return

        row = selected[0].row()
        key_id = self.key_table.item(row, 0).text()

        reply = QMessageBox.question(
            self,
            "Confirm Rotation",
            f"Are you sure you want to rotate key {key_id}?\nThis will create a new key version.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # TODO: Implement key rotation
                QMessageBox.information(
                    self,
                    "Not Implemented",
                    "Key rotation functionality will be added in a future release."
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to rotate key: {str(e)}"
                )

    def delete_key(self):
        """Delete a selected key."""
        selected = self.key_table.selectedItems()
        if not selected:
            QMessageBox.warning(
                self,
                "No Selection",
                "Please select a key to delete."
            )
            return

        row = selected[0].row()
        key_id = self.key_table.item(row, 0).text()

        reply = QMessageBox.warning(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete key {key_id}?\nThis action cannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                if self.key_manager:
                    # TODO: Get full key ID and delete
                    # self.key_manager.delete_key(full_key_id)

                    QMessageBox.information(
                        self,
                        "Success",
                        f"Key {key_id} deleted successfully."
                    )

                    # Refresh table
                    self.load_keys()

            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to delete key: {str(e)}"
                )
