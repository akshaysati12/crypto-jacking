# gui.py

import sys
import time
from collections import deque

# PyQt5 Imports
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QListWidget, QTextEdit
)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QIcon

# Matplotlib imports
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

# Local module imports (assume these exist in your project)
from system_monitor import SystemMonitor
from network_analysis import NetworkAnalyzer
from browser_detection import BrowserDetector
from alerts import AlertSystem
from logs import Logger
from prevention import PreventionTools

##############################################################################
# 1) THREAD CLASS: ONE-TIME 1-MINUTE SCAN
##############################################################################
class OneTimeScannerThread(QThread):
    """
    Scans active connections & suspicious connections for 1 minute, 
    updating results every few seconds.
    """
    scanned = pyqtSignal(list, list)         # Emitted each time we gather data
    finishedScan = pyqtSignal(str)           # Emitted after 1 minute

    def __init__(self, network_analyzer, parent=None):
        super().__init__(parent)
        self.network_analyzer = network_analyzer
        self.running = True

    def run(self):
        start_time = time.time()
        while (time.time() - start_time) < 60 and self.running:
            # 1) Gather current connections
            active = self.network_analyzer.get_active_connections()

            # 2) Detect suspicious
            suspicious = self.network_analyzer.detect_mining_connections()

            # 3) Emit data so GUI can update immediately
            self.scanned.emit(active, suspicious)

            # Sleep a bit before next iteration
            time.sleep(5)

        # Emit a final message indicating we finished scanning
        self.finishedScan.emit("Scan completed after 1 minute.")

    def stop(self):
        """
        If you need to stop earlier, call this.
        """
        self.running = False


##############################################################################
# 2) MAIN GUI CLASS
##############################################################################
class CryptoJackingGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Crypto-Jacking Detection Tool")
        self.setGeometry(100, 100, 1200, 800)

        # If you have icons:
        # self.setWindowIcon(QIcon("assets/icons/app_icon.png"))

        # Initialize modules
        self.logger = Logger()
        self.system_monitor = SystemMonitor()
        self.network_analyzer = NetworkAnalyzer(self.logger)
        self.browser_detector = BrowserDetector()
        self.alert_system = AlertSystem()
        self.prevention_tools = PreventionTools()

        # Rolling buffers for Dashboard usage charts
        self.cpu_data = deque(maxlen=20)
        self.memory_data = deque(maxlen=20)
        self.gpu_data = deque(maxlen=20)

        # Flag to indicate if a scan is currently running
        self.scan_thread = None

        # Setup the UI
        self.setup_ui()

        # Optionally, a QTimer for quick system usage updates (CPU, memory, GPU)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_dashboard_and_resources)
        self.timer.start(2000)  # every 2 seconds

    ########################################################################
    # UI SETUP
    ########################################################################
    def setup_ui(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Dashboard
        self.dashboard_tab = QWidget()
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.setup_dashboard()

        # System Resources
        self.system_tab = QWidget()
        self.tabs.addTab(self.system_tab, "System Resources")
        self.setup_system_resources()

        # Network Activity
        self.network_tab = QWidget()
        self.tabs.addTab(self.network_tab, "Network Activity")
        self.setup_network_activity()

        # Alerts and Logs
        self.alerts_tab = QWidget()
        self.tabs.addTab(self.alerts_tab, "Alerts and Logs")
        self.setup_alerts_logs()

        # Settings
        self.settings_tab = QWidget()
        self.tabs.addTab(self.settings_tab, "Settings")
        self.setup_settings()

    ########################################################################
    # DASHBOARD TAB
    ########################################################################
    def setup_dashboard(self):
        layout = QVBoxLayout()

        self.cpu_label = QLabel("CPU Usage: ")
        self.memory_label = QLabel("Memory Usage: ")
        self.gpu_label = QLabel("GPU Usage: ")
        self.threat_label = QLabel("Threats Detected: 0")

        layout.addWidget(self.cpu_label)
        layout.addWidget(self.memory_label)
        layout.addWidget(self.gpu_label)
        layout.addWidget(self.threat_label)

        # Simple real-time usage chart
        self.dashboard_fig, self.dashboard_ax = plt.subplots()
        self.dashboard_canvas = FigureCanvas(self.dashboard_fig)
        layout.addWidget(self.dashboard_canvas)

        # Table of "high usage" processes
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(4)
        self.threats_table.setHorizontalHeaderLabels(["PID", "Process Name", "CPU %", "Memory %"])
        layout.addWidget(self.threats_table)

        # Button to terminate selected threat
        self.delete_threat_button = QPushButton("Terminate Selected Threat")
        self.delete_threat_button.clicked.connect(self.delete_selected_threat)
        layout.addWidget(self.delete_threat_button)

        self.dashboard_tab.setLayout(layout)

    def update_dashboard(self):
        """
        Update CPU, memory, GPU usage, plus the high-usage processes table.
        This is called every 2 seconds by QTimer.
        """
        cpu = self.system_monitor.get_cpu_usage()
        memory = self.system_monitor.get_memory_usage()
        gpu = self.system_monitor.get_gpu_usage()
        high_usage = self.system_monitor.identify_high_usage_processes()

        # Update labels
        self.cpu_label.setText(f"CPU Usage: {cpu:.1f}%")
        self.memory_label.setText(f"Memory Usage: {memory:.1f}%")
        self.gpu_label.setText(f"GPU Usage: {gpu:.1f}%")
        self.threat_label.setText(f"Threats Detected: {len(high_usage)}")

        # Update rolling data for chart
        self.cpu_data.append(cpu)
        self.memory_data.append(memory)
        self.gpu_data.append(gpu)

        self.dashboard_ax.cla()
        self.dashboard_ax.plot(list(self.cpu_data), label="CPU", color="red")
        self.dashboard_ax.plot(list(self.memory_data), label="Memory", color="blue")
        self.dashboard_ax.plot(list(self.gpu_data), label="GPU", color="green")
        self.dashboard_ax.set_ylim(0, 100)
        self.dashboard_ax.set_title("System Usage")
        self.dashboard_ax.grid(True)
        self.dashboard_ax.legend()
        self.dashboard_canvas.draw()

        # Populate high-usage processes
        self.threats_table.setRowCount(len(high_usage))
        for row, proc in enumerate(high_usage):
            self.threats_table.setItem(row, 0, QTableWidgetItem(str(proc["pid"])))
            self.threats_table.setItem(row, 1, QTableWidgetItem(proc["name"]))
            self.threats_table.setItem(row, 2, QTableWidgetItem(str(proc["cpu_percent"])))
            self.threats_table.setItem(row, 3, QTableWidgetItem(str(proc["memory_percent"])))
        self.threats_table.resizeColumnsToContents()

    def delete_selected_threat(self):
        selected_items = self.threats_table.selectedItems()
        if not selected_items:
            self.alert_system.generate_alert("No threat selected to terminate.")
            return

        pid_item = selected_items[0]
        pid = int(pid_item.text())

        success, msg = self.prevention_tools.terminate_process(pid)
        self.alert_system.generate_alert(msg)
        self.logger.log_info(msg)

        # Refresh the table
        self.update_dashboard()

    ########################################################################
    # SYSTEM RESOURCES TAB
    ########################################################################
    def setup_system_resources(self):
        layout = QVBoxLayout()

        # CPU Chart
        self.cpu_fig, self.cpu_ax = plt.subplots()
        self.cpu_canvas = FigureCanvas(self.cpu_fig)
        layout.addWidget(QLabel("CPU Usage"))
        layout.addWidget(self.cpu_canvas)

        # Memory Chart
        self.memory_fig, self.memory_ax = plt.subplots()
        self.memory_canvas = FigureCanvas(self.memory_fig)
        layout.addWidget(QLabel("Memory Usage"))
        layout.addWidget(self.memory_canvas)

        # GPU Chart
        self.gpu_fig, self.gpu_ax = plt.subplots()
        self.gpu_canvas = FigureCanvas(self.gpu_fig)
        layout.addWidget(QLabel("GPU Usage"))
        layout.addWidget(self.gpu_canvas)

        # Process Table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(4)
        self.process_table.setHorizontalHeaderLabels(['PID', 'Name', 'CPU %', 'Memory %'])
        layout.addWidget(QLabel("Running Processes"))
        layout.addWidget(self.process_table)

        self.system_tab.setLayout(layout)

    def update_system_resources(self):
        cpu = self.system_monitor.get_cpu_usage()
        memory = self.system_monitor.get_memory_usage()
        gpu = self.system_monitor.get_gpu_usage()

        # CPU chart
        self.cpu_ax.cla()
        self.cpu_ax.plot([cpu], 'r-o')
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_ax.set_title("CPU Usage (%)")
        self.cpu_ax.grid(True)
        self.cpu_canvas.draw()

        # Memory chart
        self.memory_ax.cla()
        self.memory_ax.plot([memory], 'b-o')
        self.memory_ax.set_ylim(0, 100)
        self.memory_ax.set_title("Memory Usage (%)")
        self.memory_ax.grid(True)
        self.memory_canvas.draw()

        # GPU chart
        if isinstance(gpu, (int, float)):
            self.gpu_ax.cla()
            self.gpu_ax.plot([gpu], 'g-o')
            self.gpu_ax.set_ylim(0, 100)
            self.gpu_ax.set_title("GPU Usage (%)")
            self.gpu_ax.grid(True)
            self.gpu_canvas.draw()

        # Process table
        processes = self.system_monitor.list_processes()
        self.process_table.setRowCount(len(processes))
        for row, proc in enumerate(processes):
            self.process_table.setItem(row, 0, QTableWidgetItem(str(proc['pid'])))
            self.process_table.setItem(row, 1, QTableWidgetItem(proc['name']))
            self.process_table.setItem(row, 2, QTableWidgetItem(str(proc['cpu_percent'])))
            self.process_table.setItem(row, 3, QTableWidgetItem(str(proc['memory_percent'])))
        self.process_table.resizeColumnsToContents()

    ########################################################################
    # NETWORK ACTIVITY TAB
    ########################################################################
    def setup_network_activity(self):
        layout = QVBoxLayout()

        # Active Connections Table
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(5)
        self.connections_table.setHorizontalHeaderLabels(['PID', 'Status', 'Local Address', 'Remote Address', 'Type'])
        layout.addWidget(QLabel("Active Network Connections"))
        layout.addWidget(self.connections_table)

        # Suspicious Connections Table
        self.suspicious_table = QTableWidget()
        self.suspicious_table.setColumnCount(5)
        self.suspicious_table.setHorizontalHeaderLabels(['PID', 'Status', 'Local Address', 'Remote Address', 'Type'])
        layout.addWidget(QLabel("Suspicious Connections"))
        layout.addWidget(self.suspicious_table)

        # Prevention Buttons
        self.terminate_button = QPushButton("Terminate Selected Process")
        self.block_ip_button = QPushButton("Block Selected IP")
        self.terminate_button.clicked.connect(self.terminate_selected_process)
        self.block_ip_button.clicked.connect(self.block_selected_ip)

        # Button to start a 1-minute scan
        self.start_scan_button = QPushButton("Start Scan (1 min)")
        self.start_scan_button.clicked.connect(self.start_one_minute_scan)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.terminate_button)
        button_layout.addWidget(self.block_ip_button)
        button_layout.addWidget(self.start_scan_button)

        layout.addLayout(button_layout)
        self.network_tab.setLayout(layout)

    def start_one_minute_scan(self):
        """
        Creates and starts a OneTimeScannerThread that runs for 1 minute,
        updating the connections tables every few seconds.
        """
        if self.scan_thread and self.scan_thread.isRunning():
            self.alert_system.generate_alert("A scan is already in progress.")
            return

        # Disable the button so we can’t start again
        self.start_scan_button.setEnabled(False)

        self.scan_thread = OneTimeScannerThread(self.network_analyzer)
        self.scan_thread.scanned.connect(self.on_scanned_results)
        self.scan_thread.finishedScan.connect(self.on_scanned_finished)
        self.scan_thread.start()

        self.alert_system.generate_alert("Started 1-minute scan...")

    def on_scanned_results(self, active, suspicious):
        """
        Called periodically (every 5s) during the 1-minute scan.
        We update the Active/Suspicious tables here.
        """
        # Update Active Connections
        self.connections_table.setRowCount(len(active))
        for row, conn in enumerate(active):
            self.connections_table.setItem(row, 0, QTableWidgetItem(str(conn['pid'])))
            self.connections_table.setItem(row, 1, QTableWidgetItem(conn['status']))
            self.connections_table.setItem(row, 2, QTableWidgetItem(conn['local_address']))
            self.connections_table.setItem(row, 3, QTableWidgetItem(conn['remote_address']))
            self.connections_table.setItem(row, 4, QTableWidgetItem(conn['type']))
        self.connections_table.resizeColumnsToContents()

        # Update Suspicious Connections
        self.suspicious_table.setRowCount(len(suspicious))
        for row, conn in enumerate(suspicious):
            self.suspicious_table.setItem(row, 0, QTableWidgetItem(str(conn['pid'])))
            self.suspicious_table.setItem(row, 1, QTableWidgetItem(conn['status']))
            self.suspicious_table.setItem(row, 2, QTableWidgetItem(conn['local_address']))
            self.suspicious_table.setItem(row, 3, QTableWidgetItem(conn['remote_address']))
            self.suspicious_table.setItem(row, 4, QTableWidgetItem(conn['type']))

            # Alert/log suspicious
            alert_msg = (
                f"Suspicious connection detected: "
                f"PID={conn['pid']}, Remote={conn['remote_address']}"
            )
            self.alert_system.generate_alert(alert_msg)
            self.logger.log_threat(alert_msg)

        self.suspicious_table.resizeColumnsToContents()

    def on_scanned_finished(self, message):
        """
        Called after the 1-minute scan completes.
        We re-enable the Start Scan button and optionally show a message.
        """
        self.start_scan_button.setEnabled(True)
        self.alert_system.generate_alert(message)
        self.logger.log_info(message)

    def update_network_activity(self):
        """
        We do NOT auto-scan here. 
        The scanning is done on-demand by the OneTimeScannerThread.
        """
        pass

    def terminate_selected_process(self):
        selected_items = self.connections_table.selectedItems()
        if not selected_items:
            self.alert_system.generate_alert("No process selected to terminate.")
            return

        pid_item = selected_items[0]
        pid = int(pid_item.text())

        success, msg = self.prevention_tools.terminate_process(pid)
        self.alert_system.generate_alert(msg)
        self.logger.log_info(msg)

    def block_selected_ip(self):
        selected_items = self.suspicious_table.selectedItems()
        if not selected_items:
            self.alert_system.generate_alert("No IP selected to block.")
            return

        remote_address_item = selected_items[3]
        remote_address = remote_address_item.text()
        ip, port = self.network_analyzer.parse_address(remote_address)

        success, msg = self.prevention_tools.block_ip(ip)
        self.alert_system.generate_alert(msg)
        self.logger.log_info(msg)

    ########################################################################
    # ALERTS AND LOGS TAB
    ########################################################################
    def setup_alerts_logs(self):
        layout = QVBoxLayout()

        self.alerts_label = QLabel("Real-time Alerts:")
        layout.addWidget(self.alerts_label)
        self.alerts_list = QListWidget()
        layout.addWidget(self.alerts_list)

        self.logs_label = QLabel("Logs:")
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        layout.addWidget(self.logs_label)
        layout.addWidget(self.logs_text)

        self.alerts_tab.setLayout(layout)

        # Connect alert system
        self.alert_system.alert_signal.connect(self.display_alert)

    def display_alert(self, message):
        self.alerts_list.addItem(message)
        self.alerts_list.scrollToBottom()

    def update_alerts_logs(self):
        self.logs_text.setText(self.logger.generate_report())

    ########################################################################
    # SETTINGS TAB
    ########################################################################
    def setup_settings(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel("Settings Page - to be implemented"))
        self.settings_tab.setLayout(layout)

    ########################################################################
    # TIMER UPDATES
    ########################################################################
    def update_dashboard_and_resources(self):
        """
        Called every 2 seconds by QTimer.
        """
        self.update_dashboard()
        self.update_system_resources()
        self.update_alerts_logs()

    ########################################################################
    # CLOSE EVENT
    ########################################################################
    def closeEvent(self, event):
        """
        Stop a running scan thread if needed, then close.
        """
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(1000)  # wait up to 1 second
        event.accept()


# If you want to run gui.py standalone for testing:
# if __name__ == "__main__":
#     app = QApplication(sys.argv)
#     window = CryptoJackingGUI()
#     window.show()
#     sys.exit(app.exec_())
