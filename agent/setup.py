#!/usr/bin/env python3
"""
Honeyman Agent - Multi-Vector Threat Detection System
"""

from setuptools import setup, find_packages
import os

# Read version from __init__.py
def get_version():
    init_file = os.path.join(os.path.dirname(__file__), 'honeyman', '__init__.py')
    with open(init_file, 'r') as f:
        for line in f:
            if line.startswith('__version__'):
                return line.split('=')[1].strip().strip('"').strip("'")
    return '2.0.0'

# Read long description from README
def get_long_description():
    readme_file = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_file):
        with open(readme_file, 'r', encoding='utf-8') as f:
            return f.read()
    return ''

setup(
    name='honeyman-agent',
    version=get_version(),
    description='Mobile multi-vector threat detection platform for Raspberry Pi',
    long_description=get_long_description(),
    long_description_content_type='text/markdown',
    author='Honeyman Project',
    author_email='contact@honeymanproject.com',
    url='https://github.com/SecurityWard/honeyman-Project',
    license='MIT',

    packages=find_packages(exclude=['tests', 'tests.*']),
    include_package_data=True,

    python_requires='>=3.8',

    install_requires=[
        # Config + heartbeat
        'pyyaml>=6.0',
        'psutil>=5.9.0',

        # HTTPS transport (sensor -> backend) and central rule sync
        'aiohttp>=3.9.0',

        # Hot-reload of rules when YAML files change (rule_watcher.py).
        # Optional at runtime — agent degrades gracefully if missing —
        # but declaring it here makes `pip install .` pull it down.
        'watchdog>=3.0.0',

        # MQTT transport (optional; only used when transport.protocol == "mqtt")
        'paho-mqtt>=1.6.1',

        # Detectors
        'pyudev>=0.24.0',   # USB
        'bleak>=0.20.0',    # BLE
        'scapy>=2.5.0',     # WiFi
    ],

    extras_require={
        'gps': [
            'gpsd-py3>=0.3.0',
        ],
        'dev': [
            'pytest>=7.4.0',
            'pytest-cov>=4.1.0',
            'pytest-asyncio>=0.21.0',
            'black>=23.0.0',
            'flake8>=6.0.0',
            'mypy>=1.5.0',
        ],
    },

    entry_points={
        'console_scripts': [
            'honeyman-agent=honeyman.agent:main',
            'honeyman-ctl=honeyman.cli:main',
        ],
    },

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Monitoring',
    ],

    keywords='honeypot security threat-detection raspberry-pi iot cybersecurity',
)
