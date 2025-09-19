# network_analysis.py

import psutil
import requests
import threading
import time
import socket

class NetworkAnalyzer:
    def __init__(self, logger=None):
        """
        :param logger: Optional logger instance if you want to log info/warnings.
        """
        self.logger = logger
        self.active_connections = []
        self.blacklist = set()
        self.blacklist_lock = threading.Lock()

        # Load the initial blacklist and start a background thread to update it
        self.load_blacklist()
        self.updater_thread = threading.Thread(
            target=self.update_blacklist_periodically, 
            daemon=True
        )
        self.updater_thread.start()

    def load_blacklist(self):
        """
        Load or initialize a predefined set of mining pool domains.
        Extend this method if you want to load from a file or another local resource.
        """
        self.blacklist = {
            'miningpool1.com',
            'miningpool2.net',
            'exampleminingpool.io'
        }
        # If you want to fetch from an external resource during initialization, do it here.

    def update_blacklist_periodically(self, interval=86400):
        """
        Run as a background thread, periodically updating the blacklist (every 24 hours by default).
        """
        while True:
            self.update_blacklist()
            time.sleep(interval)

    def update_blacklist(self):
        """
        Placeholder method for fetching updated mining pool domains 
        from external APIs (e.g., VirusTotal or custom endpoints).
        """
        # Example skeleton:
        #
        # url = "https://example.com/mining-pools"
        # try:
        #     response = requests.get(url)
        #     if response.status_code == 200:
        #         new_pools = response.json()
        #         with self.blacklist_lock:
        #             self.blacklist.update(new_pools)
        # except Exception as e:
        #     if self.logger:
        #         self.logger.log_info(f"Error updating blacklist: {e}")
        #
        pass

    def get_active_connections(self):
        """
        Collects all active inet connections using psutil, 
        storing them in self.active_connections and returning the list.
        """
        connections = psutil.net_connections(kind='inet')
        self.active_connections = []

        for conn in connections:
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""

            # Determine if it's TCP or UDP by checking the socket type
            conn_type = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'

            self.active_connections.append({
                'pid': conn.pid,
                'status': conn.status,
                'local_address': laddr,
                'remote_address': raddr,
                'type': conn_type
            })

        return self.active_connections

    def detect_mining_connections(self):
        """
        Checks current self.active_connections against the blacklist to identify suspicious connections.
        """
        suspicious = []
        with self.blacklist_lock:
            current_blacklist = self.blacklist.copy()

        for conn in self.active_connections:
            if conn['remote_address']:
                remote_ip, remote_port = self.parse_address(conn['remote_address'])
                domain = self.ip_to_domain(remote_ip)
                # If the resolved domain is in the blacklist, flag it as suspicious
                if domain and domain.lower() in current_blacklist:
                    suspicious.append(conn)

        return suspicious

    def parse_address(self, address):
        """
        Splits an address string 'ip:port' into (ip, port) tuple. 
        If splitting fails, returns (address, '').
        """
        try:
            ip, port = address.split(':')
            return ip, port
        except ValueError:
            return address, ''

    def ip_to_domain(self, ip):
        """
        Attempts a reverse DNS lookup on the given IP to get its domain name.
        Returns an empty string on failure or if no domain is found.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return ''
        except Exception:
            # If you have a logger, you can log the exception here
            return ''

    def monitor_data_flow(self):
        """
        Returns a dict with the system-wide bytes sent/received since boot.
        """
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv
        }
