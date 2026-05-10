import logging
import os
import sys
import time
from contextlib import contextmanager

# ============================================================
# Centralized Logging Configuration
# ============================================================

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

class VigilantLinkFormatter(logging.Formatter):
    """
    Custom formatter to support structured prefixes like [PHASE1], [SCORING], etc.
    """
    def format(self, record):
        # We can handle custom attributes here if needed, 
        # but for now we just rely on standard formatting.
        return super().format(record)

def setup_logging():
    # Clear existing handlers
    root_logger = logging.getLogger()
    if root_logger.handlers:
        for handler in root_logger.handlers:
            root_logger.removeHandler(handler)

    # Base configuration
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        format="%(levelname)s: %(message)s",
        stream=sys.stdout
    )

    # Suppress noise from third-party libraries
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING) # Reduce polling noise
    logging.getLogger("playwright").setLevel(logging.WARNING)

    # Force Windows suppression if needed
    if sys.platform == 'win32':
        logging.getLogger('asyncio').setLevel(logging.CRITICAL)

@contextmanager
def log_duration(prefix: str, name: str):
    """
    Utility to log the duration of a block of code.
    Example:
    with log_duration("[PHASE1]", "Total execution"):
        ...
    """
    start = time.monotonic()
    yield
    duration = (time.monotonic() - start) * 1000
    logging.getLogger("VigilantLink").info(f"{prefix} [TIMING] {name} completed in {duration:.2f}ms")

def get_logger(name: str):
    return logging.getLogger(name)
