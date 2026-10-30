#!/usr/bin/env python3
import sys
from PySide6.QtWidgets import QApplication
from zapret2_gui.ui.main_window import MainWindow

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MainWindow(); w.show()
    sys.exit(app.exec())
