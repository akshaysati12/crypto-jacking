# worker.py

import time
from PyQt5.QtCore import QObject, QTimer, pyqtSignal

class ScanWorker(QObject):
    """
    Worker that performs the scanning in a background thread.
    It uses a QTimer internally to run scans every X milliseconds
    without blocking the main GUI thread.
    """
    # We define signals to send data back to the GUI.
    # Each signal can carry data relevant to a specific tab.
    dashboard_data_ready = pyqtSignal(dict)     # For CPU/mem/GPU usage & high-usage processes
    system_data_ready = pyqtSignal(dict)        # For system resources: CPU, memory, GPU, full process list
    network_data_ready = pyqtSignal(dict)       # For network activity: active & suspicious connections
    logs_data_ready = pyqtSignal(str)           # For updated logs text

    def __init__(self, system_monitor, network_analyzer, browser_detector, logger, prevention_tools, parent=None):
        super().__init__(parent)
        self.system_monitor = system_monitor
        self.network_analyzer = network_analyzer
        self.browser_detector = browser_detector
        self.logger = logger
        self.prevention_tools = prevention_tools

        self._interval_ms = 2000  # default: 2 seconds
        self._running = True

        # Create a QTimer to schedule repeated scans
        self.timer = QTimer()
        self.timer.timeout.connect(self.perform_scan)

    def start_scanning(self, interval_ms=2000):
        """
        Start periodic scanning every 'interval_ms' milliseconds.
        """
        self._interval_ms = interval_ms
        self.timer.start(self._interval_ms)

    def stop_scanning(self):
        """ Stop periodic scanning. """
        self.timer.stop()
        self._running = False

    def perform_scan(self):
        """
        Perform scanning tasks (same logic that was in update_all_tabs),
        then emit signals with the results so the GUI can update.
        """
        if not self._running:
            return

        # 1) Dashboard-like data
        cpu = self.system_monitor.get_cpu_usage()
        memory = self.system_monitor.get_memory_usage()
        gpu = self.system_monitor.get_gpu_usage()
        high_usage = self.system_monitor.identify_high_usage_processes()

        dashboard_payload = {
            'cpu': cpu,
            'memory': memory,
            'gpu': gpu,
            'high_usage': high_usage
        }
        self.dashboard_data_ready.emit(dashboard_payload)

        # 2) System resources data
        all_processes = self.system_monitor.list_processes()
        system_payload = {
            'cpu': cpu,
            'memory': memory,
            'gpu': gpu,
            'processes': all_processes
        }
        self.system_data_ready.emit(system_payload)

        # 3) Network activity
        self.network_analyzer.get_active_connections()
        suspicious = self.network_analyzer.detect_mining_connections()
        network_payload = {
            'connections': self.network_analyzer.active_connections,
            'suspicious': suspicious
        }
        self.network_data_ready.emit(network_payload)

        # 4) Logs data
        logs_text = self.logger.generate_report()
        self.logs_data_ready.emit(logs_text)

        # (Browser detection, additional checks, etc. could go here)

        # Repeat on next timer tick. By default, the QTimer calls this method again.


    def terminate_process(self, pid):
        """
        If you want the worker to handle process termination so it won't block the GUI,
        you can define that here. But typically you handle user-initiated termination in the GUI.
        """
        return self.prevention_tools.terminate_process(pid)
