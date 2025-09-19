# logs.py
import logging
from datetime import datetime

class Logger:
    def __init__(self, log_file='crypto_jacking_logs.log'):
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def log_threat(self, threat_details):
        logging.warning(f"Threat Detected: {threat_details}")

    def log_info(self, info):
        logging.info(info)

    def generate_report(self):
        try:
            with open('crypto_jacking_logs.log', 'r') as file:
                return file.read()
        except FileNotFoundError:
            return "No logs available."
