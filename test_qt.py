import sys
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget

def test_qt():
    app = QApplication(sys.argv)
    
    # Create a simple window
    window = QWidget()
    window.setWindowTitle('PyQt6 Test')
    window.setGeometry(100, 100, 400, 200)
    
    # Add a label
    label = QLabel('PyQt6 is working correctly!', parent=window)
    label.move(50, 50)
    
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    test_qt()
