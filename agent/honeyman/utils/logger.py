#!/usr/bin/env python3
"""Logging configuration"""

import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any


def setup_logger(config: Dict[str, Any]):
    """
    Setup logging configuration

    Args:
        config: Logging configuration
    """
    level = config.get('level', 'INFO')
    log_file = config.get('file', '/var/log/honeyman/agent.log')
    max_bytes = config.get('max_bytes', 10 * 1024 * 1024)  # 10MB
    backup_count = config.get('backup_count', 5)

    # Create log directory if needed
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)

    # File handler (rotating)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count
    )
    file_handler.setLevel(getattr(logging, level.upper()))
    file_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_format)
    root_logger.addHandler(file_handler)
