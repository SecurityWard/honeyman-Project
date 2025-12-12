"""
Honeyman Agent - Multi-Vector Threat Detection System

A modular, rule-based threat detection platform for Raspberry Pi
and embedded systems.
"""

__version__ = '2.0.0'
__author__ = 'Honeyman Project'
__license__ = 'MIT'

from .agent import HoneymanAgent
from .core.config_manager import ConfigManager

__all__ = ['HoneymanAgent', 'ConfigManager']
