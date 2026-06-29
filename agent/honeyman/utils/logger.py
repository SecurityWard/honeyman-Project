"""Logging configuration.

The file handler is the primary log surface — operators read
/var/log/honeyman/agent.log. The console handler stays at WARNING so
systemd's journal only sees real problems (startup, errors, restarts),
not every threat detection at INFO. Without that cap, every USB plug-in
and BLE match would land in `journalctl -u honeyman-agent`, drowning
the lifecycle signal in detection noise.
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any


def setup_logger(config: Dict[str, Any]):
    level = config.get('level', 'INFO')
    log_file = config.get('file', '/var/log/honeyman/agent.log')
    max_bytes = config.get('max_bytes', 10 * 1024 * 1024)
    backup_count = config.get('backup_count', 5)

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    fmt = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )

    # Console / systemd-journal handler: warnings and above only.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(fmt)
    root_logger.addHandler(console_handler)

    # File handler honours the configured level (INFO by default).
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count,
    )
    file_handler.setLevel(getattr(logging, level.upper()))
    file_handler.setFormatter(fmt)
    root_logger.addHandler(file_handler)
