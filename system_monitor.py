# system_monitor.py
import psutil
import time
import GPUtil

class SystemMonitor:
    def __init__(self):
        self.process_info = []

    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=1)

    def get_memory_usage(self):
        mem = psutil.virtual_memory()
        return mem.percent

    def get_gpu_usage(self):
        gpus = GPUtil.getGPUs()
        if gpus:
            # Return the average GPU load across all GPUs
            return sum([gpu.load for gpu in gpus]) / len(gpus) * 100
        else:
            return 0

    def list_processes(self):
        self.process_info = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                self.process_info.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return self.process_info

    def identify_high_usage_processes(self, cpu_threshold=20, memory_threshold=30):
        high_usage = []
        for proc in self.process_info:
            if proc['cpu_percent'] > cpu_threshold or proc['memory_percent'] > memory_threshold:
                high_usage.append(proc)
        return high_usage
