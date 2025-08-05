import os
import sys

class Config:
    # Default values
    DEFAULTS = {
        'DEBUG': '0',
        'COMMAND_TIMEOUT': '300',
        'MEMORY_THRESHOLD': '0.8',
        'WORDLISTS_MAX_MB': '200',
        'SCANS_MAX_MB': '500',
        'RAG_MAX_DOCS': '10000',
        'RAG_MAX_MB': '500',
        'EXPORT_SERVER_URL': 'https://your-server/upload',
    }
    
    def __init__(self):
        self.reload()

    def reload(self):
        self.DEBUG = os.getenv('DEBUG', self.DEFAULTS['DEBUG']) == '1'
        self.COMMAND_TIMEOUT = self._validate_int('COMMAND_TIMEOUT', 1, 86400)
        self.MEMORY_THRESHOLD = self._validate_float('MEMORY_THRESHOLD', 0.0, 1.0)
        self.WORDLISTS_MAX_MB = self._validate_int('WORDLISTS_MAX_MB', 1, 10000)
        self.SCANS_MAX_MB = self._validate_int('SCANS_MAX_MB', 1, 10000)
        self.RAG_MAX_DOCS = self._validate_int('RAG_MAX_DOCS', 100, 1000000)
        self.RAG_MAX_MB = self._validate_int('RAG_MAX_MB', 1, 10000)
        self.EXPORT_SERVER_URL = os.getenv('EXPORT_SERVER_URL', self.DEFAULTS['EXPORT_SERVER_URL'])
        # Add more config as needed

    def _validate_int(self, key, minval, maxval):
        val = os.getenv(key, self.DEFAULTS[key])
        try:
            ival = int(val)
            if not (minval <= ival <= maxval):
                print(f"[CONFIG ERROR] {key}={ival} is out of range ({minval}-{maxval})")
                sys.exit(1)
            return ival
        except Exception:
            print(f"[CONFIG ERROR] {key}={val} is not a valid integer")
            sys.exit(1)

    def _validate_float(self, key, minval, maxval):
        val = os.getenv(key, self.DEFAULTS[key])
        try:
            fval = float(val)
            if not (minval <= fval <= maxval):
                print(f"[CONFIG ERROR] {key}={fval} is out of range ({minval}-{maxval})")
                sys.exit(1)
            return fval
        except Exception:
            print(f"[CONFIG ERROR] {key}={val} is not a valid float")
            sys.exit(1)

# Usage:
# from lib.config import Config
# config = Config()
# config.reload()  # To reload at runtime
# print(config.COMMAND_TIMEOUT)