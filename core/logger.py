"""Logging configuration for Security Suite."""

import logging
import sys
from pathlib import Path


def setup_logging(level=logging.INFO, logfile=None):
    """Configure logging without duplicating handlers on repeated calls."""

    if logfile:
        Path(logfile).parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    for handler in list(root_logger.handlers):
        if getattr(handler, "_security_suite_handler", False):
            root_logger.removeHandler(handler)
            handler.close()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler._security_suite_handler = True
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    if logfile:
        file_handler = logging.FileHandler(logfile, encoding="utf-8")
        file_handler._security_suite_handler = True
        file_handler.setLevel(level)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def get_logger(name):
    """Get a logger instance for a module."""
    return logging.getLogger(name)
