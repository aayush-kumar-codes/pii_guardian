import logging
import os
import sys
from typing import Optional

def setup_logger(
    logger_name: str,
    log_level_str: Optional[str] = None,
    log_file: Optional[str] = None
) -> logging.Logger:
    """Set up a logger with consistent formatting"""
    # Set log level from environment or default to INFO
    log_level_map = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }

    log_level_str = log_level_str or os.environ.get('LOG_LEVEL', 'INFO')
    log_level = log_level_map.get(log_level_str.upper(), logging.INFO)

    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)

    # Avoid adding duplicate handlers
    if logger.handlers:
        return logger

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Setup console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Setup file handler if log file specified
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
