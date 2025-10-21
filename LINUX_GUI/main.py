#!/usr/bin/env python3
"""
SecureVault - Linux GUI Application
"""
import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QWidget,
                            QPushButton, QLabel, QStackedWidget, QMessageBox)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QIcon, QFont

# Add the parent directory to the path to import secure_vault modules
sys.path.insert(0, str(Path(__file__).parent.parent))

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureVault")
        self.setMinimumSize(800, 600)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QPushButton {
                background-color: #4a86e8;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #3a76d8;
            }
        """)
        
        # Main widget and layout
        self.main_widget = QWidget()
        self.main_layout = QVBoxLayout(self.main_widget)
        self.setCentralWidget(self.main_widget)
        
        # Stacked widget for different views
        self.stacked_widget = QStackedWidget()
        self.main_layout.addWidget(self.stacked_widget)
        
        # Create and add main menu
        self.create_main_menu()
        
    def create_main_menu(self):
        """Create the main menu widget"""
        menu_widget = QWidget()
        layout = QVBoxLayout(menu_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Title
        title = QLabel("SecureVault")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Buttons
        btn_encrypt = QPushButton("Encrypt File")
        btn_encrypt.clicked.connect(self.show_encrypt_view)
        btn_encrypt.setMinimumHeight(40)
        
        btn_decrypt = QPushButton("Decrypt File")
        btn_decrypt.clicked.connect(self.show_decrypt_view)
        btn_decrypt.setMinimumHeight(40)
        
        btn_key_manager = QPushButton("Key Manager")
        btn_key_manager.clicked.connect(self.show_key_manager)
        btn_key_manager.setMinimumHeight(40)
        
        # Add widgets to layout
        layout.addStretch()
        layout.addWidget(title)
        layout.addSpacing(30)
        layout.addWidget(btn_encrypt)
        layout.addWidget(btn_decrypt)
        layout.addWidget(btn_key_manager)
        layout.addStretch()
        
        self.stacked_widget.addWidget(menu_widget)
    
    def show_encrypt_view(self):
        QMessageBox.information(self, "Info", "Encrypt view will be implemented here")
    
    def show_decrypt_view(self):
        QMessageBox.information(self, "Info", "Decrypt view will be implemented here")
    
    def show_key_manager(self):
        QMessageBox.information(self, "Info", "Key manager will be implemented here")

def main():
    app = QApplication(sys.argv)
    
    # Set application info
    app.setApplicationName("SecureVault")
    app.setApplicationVersion("1.0.0")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
