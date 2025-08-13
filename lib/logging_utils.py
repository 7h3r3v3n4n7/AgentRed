import os
import logging

# Configure logging based on DEBUG environment variable
if os.getenv("DEBUG") == "1":
    logging.basicConfig(level=logging.DEBUG, format="[DEBUG] %(message)s")
else:
    logging.basicConfig(level=logging.INFO)

def debug_print(*args, **kwargs):
    """Log debug messages when the DEBUG environment variable is set."""
    if os.getenv("DEBUG") == "1":
        logging.debug(" ".join(str(a) for a in args))
