"""Activity monitor view for SecureVault."""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
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

from audit_logger import AuditEventType, AuditLogger, AuditSeverity, get_audit_logger


class ActivityMonitorView(QWidget):
    """Displays recent audit events with simple filtering controls."""

    back_requested = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.audit_logger: AuditLogger = get_audit_logger()
        self._current_severity: Optional[AuditSeverity] = None
        self._current_event: Optional[AuditEventType] = None
        self._setup_ui()
        self.refresh_events()

    # UI -----------------------------------------------------------------
    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 20, 40, 20)

        title = QLabel("Activity Monitor")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(title)

        filter_layout = QHBoxLayout()
        filter_layout.setSpacing(12)

        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All severities", userData=None)
        for severity in AuditSeverity:
            self.severity_filter.addItem(severity.value.title(), userData=severity)
        self.severity_filter.currentIndexChanged.connect(self._on_filter_changed)

        self.event_filter = QComboBox()
        self.event_filter.addItem("All event types", userData=None)
        for event in AuditEventType:
            self.event_filter.addItem(event.value.replace("_", " ").title(), userData=event)
        self.event_filter.currentIndexChanged.connect(self._on_filter_changed)

        filter_layout.addWidget(QLabel("Severity:"))
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addSpacing(20)
        filter_layout.addWidget(QLabel("Event:"))
        filter_layout.addWidget(self.event_filter)
        filter_layout.addStretch()

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh_events)
        filter_layout.addWidget(self.refresh_button)

        layout.addLayout(filter_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Time", "Severity", "Event", "Message"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table, 1)

        button_row = QHBoxLayout()
        button_row.addStretch()
        back_btn = QPushButton("Back")
        back_btn.clicked.connect(self.back_requested.emit)
        button_row.addWidget(back_btn)
        layout.addLayout(button_row)

    # Event handling -----------------------------------------------------
    def _on_filter_changed(self) -> None:
        self._current_severity = self.severity_filter.currentData()
        self._current_event = self.event_filter.currentData()
        self.refresh_events()

    def refresh_events(self) -> None:
        """Load events from the audit log and render them."""
        severity = self._current_severity
        event = self._current_event

        events = self.audit_logger.query_events(
            severity=severity,
            event_type=event,
            limit=250,
        )

        self.table.setRowCount(len(events))
        for row, event_data in enumerate(events):
            timestamp = datetime.fromtimestamp(event_data["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            severity_text = event_data.get("severity", "").title()
            event_text = event_data.get("event_type", "").replace("_", " ").title()
            message = event_data.get("message", "")

            self.table.setItem(row, 0, QTableWidgetItem(timestamp))
            self.table.setItem(row, 1, QTableWidgetItem(severity_text))
            self.table.setItem(row, 2, QTableWidgetItem(event_text))
            item = QTableWidgetItem(message)
            item.setToolTip(message)
            self.table.setItem(row, 3, item)

        self.table.resizeColumnsToContents()
