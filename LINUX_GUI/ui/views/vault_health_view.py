"""Vault health check view."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

project_root = str(Path(__file__).parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from vault_health import VaultHealthEvaluator


class VaultHealthView(QWidget):
    """Runs and displays the results of vault health checks."""

    back_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.evaluator = VaultHealthEvaluator()
        self._setup_ui()

    # UI -----------------------------------------------------------------
    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 20, 40, 20)

        title = QLabel("Vault Health Check")
        title.setObjectName("title")
        layout.addWidget(title)

        self.summary_label = QLabel("Run the health check to inspect your vault.")
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Check", "Status", "Details", "Remediation"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

        button_row = QHBoxLayout()
        self.run_button = QPushButton("Run Health Check")
        self.run_button.clicked.connect(self.run_checks)
        button_row.addWidget(self.run_button)
        button_row.addStretch()
        back_button = QPushButton("Back")
        back_button.clicked.connect(self.back_requested.emit)
        button_row.addWidget(back_button)
        layout.addLayout(button_row)

    # Actions -------------------------------------------------------------
    def run_checks(self) -> None:
        overall, results = self.evaluator.run_checks()
        self.summary_label.setText(f"Overall vault status: <b>{overall}</b>")

        self.table.setRowCount(len(results))
        for row, result in enumerate(results):
            self.table.setItem(row, 0, QTableWidgetItem(result.name))
            status_item = QTableWidgetItem(result.status)
            if result.status == "Healthy":
                status_item.setForeground(Qt.GlobalColor.darkGreen)
            elif result.status == "Warning":
                status_item.setForeground(Qt.GlobalColor.darkYellow)
            else:
                status_item.setForeground(Qt.GlobalColor.darkRed)
            self.table.setItem(row, 1, status_item)
            self.table.setItem(row, 2, QTableWidgetItem(result.details))
            remediation = result.remediation or "No action required."
            self.table.setItem(row, 3, QTableWidgetItem(remediation))

        self.table.resizeColumnsToContents()

    def showEvent(self, event) -> None:  # noqa: D401 - Qt override
        super().showEvent(event)
        self.run_checks()
