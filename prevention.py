# prevention.py
import psutil
import subprocess

class PreventionTools:
    def terminate_process(self, pid):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)
            return True, f"Process '{proc.name()}' (PID: {pid}) terminated successfully."
        except psutil.NoSuchProcess:
            return False, "Process does not exist."
        except psutil.AccessDenied:
            return False, "Access denied to terminate process."
        except psutil.TimeoutExpired:
            return False, "Process termination timed out."

    def block_ip(self, ip):
        # Implement IP blocking using Windows firewall
        # This requires administrative privileges
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                            'name=BlockCryptoJackingIP', 'dir=out', 'action=block',
                            f'remoteip={ip}'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True, f"IP {ip} has been blocked successfully."
        except subprocess.CalledProcessError as e:
            return False, f"Failed to block IP {ip}. Error: {e.stderr.decode()}"

    def unblock_ip(self, ip):
        # Remove the firewall rule blocking the IP
        try:
            subprocess.run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            'name=BlockCryptoJackingIP', f'remoteip={ip}'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True, f"IP {ip} has been unblocked successfully."
        except subprocess.CalledProcessError as e:
            return False, f"Failed to unblock IP {ip}. Error: {e.stderr.decode()}"

    def manage_whitelist(self, ip, action='add'):
        # Implement whitelist management by adding/removing firewall rules
        # Placeholder: Implement as needed
        pass

    def manage_blacklist(self, ip, action='add'):
        # Implement blacklist management by adding/removing firewall rules
        # Placeholder: Implement as needed
        pass
