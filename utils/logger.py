import logging
import json
from datetime import datetime
from flask import request
import os

class SecurityLogger:
    # Create a class to handle security logs for events like login, downloads, etc.

    def __init__(self, log_file='logs/security.log'):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        self.logger = logging.getLogger('security')
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log_event(self, event_type, user_id, details, severity='INFO'):
        """Log a security event in JSON format"""
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'user_id': user_id,
            'ip_address': request.remote_addr if request else None,
            'user_agent': request.headers.get('User-Agent') if request else None,
            'details': details,
            'severity': severity
        }

        log_str = json.dumps(log_entry) # Convert dictionary to JSON string
        if severity == 'CRITICAL':
            self.logger.critical(log_str) # Log as CRITICAL
        elif severity == 'ERROR':
            self.logger.error(log_str) # Log as ERROR
        elif severity == 'WARNING':
            self.logger.warning(log_str) # Log as WARNING
        else:
            self.logger.info(log_str) # Log as INFO (default)