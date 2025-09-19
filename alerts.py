# alerts.py
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtCore import QObject, pyqtSignal

class AlertSystem(QObject):
    alert_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.alert_signal.connect(self.show_alert)

    def generate_alert(self, message):
        self.alert_signal.emit(message)

    def show_alert(self, message):
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Crypto-Jacking Alert")
        msg_box.setText(message)
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()
