"""Secure notes view for SecureVault."""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from typing import Callable, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

project_root = str(Path(__file__).parent.parent.parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from secure_notes import SecureNote, SecureNotesVault


class NoteEditorDialog(QDialog):
    """Simple dialog for creating or editing a secure note."""

    def __init__(self, title: str, body: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Secure Note")
        layout = QVBoxLayout(self)

        layout.addWidget(QLabel("Title"))
        self.title_edit = QLineEdit(title)
        layout.addWidget(self.title_edit)

        layout.addWidget(QLabel("Body"))
        self.body_edit = QPlainTextEdit(body)
        self.body_edit.setMinimumSize(400, 240)
        layout.addWidget(self.body_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_values(self) -> tuple[str, str]:
        return self.title_edit.text().strip(), self.body_edit.toPlainText().rstrip()


class SecureNotesView(QWidget):
    """Allows users to manage encrypted secure notes."""

    back_requested = pyqtSignal()

    def __init__(
        self,
        session_provider: Optional[Callable[[], Optional[object]]] = None,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.session_provider = session_provider or (lambda: None)
        self.vault = SecureNotesVault(session_provider=self.session_provider)
        self.notes: List[SecureNote] = []
        self._setup_ui()
        self.load_notes()

    # UI -----------------------------------------------------------------
    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(24)

        sidebar = QVBoxLayout()
        sidebar.addWidget(QLabel("Secure Notes"))

        self.list_widget = QListWidget()
        self.list_widget.itemSelectionChanged.connect(self._on_note_selected)
        sidebar.addWidget(self.list_widget, 1)

        button_row = QHBoxLayout()
        self.add_button = QPushButton("Add")
        self.add_button.clicked.connect(self.add_note)
        self.edit_button = QPushButton("Edit")
        self.edit_button.clicked.connect(self.edit_note)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_note)
        button_row.addWidget(self.add_button)
        button_row.addWidget(self.edit_button)
        button_row.addWidget(self.delete_button)
        sidebar.addLayout(button_row)

        back_button = QPushButton("Back")
        back_button.clicked.connect(self.back_requested.emit)
        sidebar.addWidget(back_button)

        layout.addLayout(sidebar, 1)

        detail_layout = QVBoxLayout()
        self.detail_title = QLabel("Select a note")
        self.detail_title.setObjectName("title")
        detail_layout.addWidget(self.detail_title)

        self.detail_body = QPlainTextEdit()
        self.detail_body.setReadOnly(True)
        detail_layout.addWidget(self.detail_body, 1)

        layout.addLayout(detail_layout, 2)

    # Data handling ------------------------------------------------------
    def load_notes(self) -> None:
        try:
            self.notes = self.vault.load_notes()
        except Exception as exc:
            QMessageBox.warning(self, "Secure Notes", f"Failed to load notes: {exc}")
            self.notes = []

        self._refresh_list()

    def save_notes(self) -> None:
        try:
            self.vault.save_notes(self.notes)
        except Exception as exc:
            QMessageBox.warning(self, "Secure Notes", f"Failed to save notes: {exc}")

    def _refresh_list(self) -> None:
        self.list_widget.clear()
        for note in self.notes:
            item = QListWidgetItem(note.title or "(Untitled note)")
            item.setData(Qt.ItemDataRole.UserRole, note.note_id)
            self.list_widget.addItem(item)

        if self.notes:
            self.list_widget.setCurrentRow(0)
        else:
            self.detail_title.setText("No secure notes yet")
            self.detail_body.setPlainText("")

    # Actions ------------------------------------------------------------
    def _find_note_by_id(self, note_id: str) -> Optional[SecureNote]:
        for note in self.notes:
            if note.note_id == note_id:
                return note
        return None

    def _on_note_selected(self) -> None:
        current = self.list_widget.currentItem()
        if not current:
            self.detail_title.setText("Select a note")
            self.detail_body.setPlainText("")
            return

        note_id = current.data(Qt.ItemDataRole.UserRole)
        note = self._find_note_by_id(note_id)
        if note:
            self.detail_title.setText(note.title or "(Untitled note)")
            self.detail_body.setPlainText(note.body)

    def add_note(self) -> None:
        dialog = NoteEditorDialog("", "", self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        title, body = dialog.get_values()
        if not title and not body:
            QMessageBox.information(self, "Secure Notes", "Cannot save an empty note.")
            return

        now = time.time()
        new_note = SecureNote(
            note_id=str(uuid.uuid4()),
            title=title,
            body=body,
            created_at=now,
            updated_at=now,
        )
        self.notes.append(new_note)
        self.save_notes()
        self._refresh_list()

    def edit_note(self) -> None:
        current = self.list_widget.currentItem()
        if not current:
            QMessageBox.information(self, "Secure Notes", "Select a note to edit.")
            return

        note = self._find_note_by_id(current.data(Qt.ItemDataRole.UserRole))
        if not note:
            return

        dialog = NoteEditorDialog(note.title, note.body, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        title, body = dialog.get_values()
        if not title and not body:
            QMessageBox.information(self, "Secure Notes", "Cannot save an empty note.")
            return

        note.title = title
        note.body = body
        note.updated_at = time.time()
        self.save_notes()
        self._refresh_list()

    def delete_note(self) -> None:
        current = self.list_widget.currentItem()
        if not current:
            QMessageBox.information(self, "Secure Notes", "Select a note to delete.")
            return

        note = self._find_note_by_id(current.data(Qt.ItemDataRole.UserRole))
        if not note:
            return

        confirm = QMessageBox.question(
            self,
            "Delete note",
            f"Delete '{note.title or 'Untitled note'}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.notes = [n for n in self.notes if n.note_id != note.note_id]
        self.save_notes()
        self._refresh_list()
