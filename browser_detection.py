# browser_detection.py
import psutil
from bs4 import BeautifulSoup
import requests

class BrowserDetector:
    def __init__(self):
        self.suspicious_scripts = []

    def get_browser_processes(self):
        browsers = ['chrome', 'firefox', 'edge', 'opera']
        browser_procs = []
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] and proc.info['name'].lower() in browsers:
                browser_procs.append(proc)
        return browser_procs

    def analyze_scripts(self):
        # Placeholder: Access browser's open tabs and inspect scripts
        # Accessing browser internals requires specific APIs or extensions
        # Here, we simulate detection by checking known mining script patterns
        # Alternatively, monitor network requests for mining script URLs
        # Implementing this accurately is complex; consider integrating with browser extensions
        self.suspicious_scripts = []
        # Example pattern
        mining_script_patterns = ['coinhive', 'miner', 'cryptonight', 'nicehash']
        # Simulate detection by searching for patterns in open network connections
        # This is a simplification and may not accurately detect mining scripts
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.raddr:
                remote_ip, remote_port = conn.raddr
                domain = self.ip_to_domain(remote_ip)
                if domain:
                    for pattern in mining_script_patterns:
                        if pattern in domain.lower():
                            self.suspicious_scripts.append({
                                'pid': conn.pid,
                                'remote_domain': domain,
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'pattern': pattern
                            })
        return self.suspicious_scripts

    def ip_to_domain(self, ip):
        try:
            import socket
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except socket.herror:
            return ''

    def block_script(self, script_detail):
        # Implement script blocking, possibly by terminating browser process or modifying browser settings
        # This is non-trivial and may require browser extensions or deeper system integration
        # For simplicity, terminate the browser process associated with the script
        pid = script_detail.get('pid')
        if pid:
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                return True, f"Terminated browser process {proc.name()} (PID: {pid}) due to suspicious script."
            except psutil.NoSuchProcess:
                return False, "Process does not exist."
            except psutil.AccessDenied:
                return False, "Access denied to terminate process."
        return False, "Invalid script details."

    def monitor_browser_scripts(self):
        # Periodically monitor for suspicious scripts
        # This can be integrated with the main monitoring loop
        return self.analyze_scripts()
