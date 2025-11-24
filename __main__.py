import sys
from PyQt5.QtWidgets import QApplication
import qdarkstyle
from main_app import PasswordVaultApp

def main():
    app = QApplication(sys.argv)

    # Optional dark theme
    try:
        app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
    except Exception:
        pass

    main_window = PasswordVaultApp()
    main_window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
