#!/usr/bin/env python3
"""
USB Threat Detector - V2

Detects malicious USB devices including:
- BadUSB/Rubber Ducky
- OMG Cables
- Bash Bunny
- USB malware
- Autorun abuse
- Stuxnet and other APT malware
"""

import asyncio
import logging
import os
import hashlib
import sqlite3
import pyudev
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

from .base_detector import BaseDetector

logger = logging.getLogger(__name__)


class UsbDetector(BaseDetector):
    """
    USB threat detection using pyudev monitoring

    Detects threats via:
    - Hardware signatures (VID/PID matching)
    - Malware hash database
    - File-based detection (autorun, executables)
    - Volume label patterns
    - Behavioral analysis
    """

    def __init__(self, rule_engine, transport, config, location_service):
        super().__init__(rule_engine, transport, config, location_service)

        # System device whitelist (don't alert on these)
        self.SYSTEM_WHITELIST = {
            '046d': 'Logitech',  # Keyboards, mice
            '1d6b': 'Linux Foundation',  # USB hubs
            '8087': 'Intel Bluetooth',
            '0a5c': 'Broadcom Bluetooth',
            '0bda': 'Realtek',
        }

        self.context = None
        self.monitor = None
        self.known_devices = {}
        self.hash_db = None

        # Initialize malware hash database
        self._init_hash_database()

    def _init_hash_database(self):
        """Initialize connection to malware hash database"""
        try:
            db_path = self.config.get('usb.hash_database_path',
                                     '/etc/honeyman/data/malware_hashes.db')

            if os.path.exists(db_path):
                self.hash_db = sqlite3.connect(db_path, check_same_thread=False)
                self.hash_db.row_factory = sqlite3.Row

                # Get hash count
                cursor = self.hash_db.cursor()
                cursor.execute('SELECT COUNT(*) FROM malware_hashes')
                count = cursor.fetchone()[0]

                logger.info(f"Loaded malware hash database: {count} signatures")
            else:
                logger.warning(f"Malware hash database not found: {db_path}")
                self.hash_db = None

        except Exception as e:
            logger.error(f"Failed to initialize hash database: {e}")
            self.hash_db = None

    async def initialize(self):
        """Initialize USB monitoring via pyudev"""
        try:
            # Create udev context
            self.context = pyudev.Context()

            # Create monitor for USB devices
            self.monitor = pyudev.Monitor.from_netlink(self.context)
            self.monitor.filter_by('usb')

            logger.info("USB detector initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize USB detector: {e}")
            raise RuntimeError(f"USB detector initialization failed: {e}")

    async def detect(self):
        """Main USB detection loop"""
        logger.info("USB detector starting detection loop...")

        # Start monitoring
        self.monitor.start()

        try:
            while self.running:
                # Poll for USB events (non-blocking with timeout)
                device = self.monitor.poll(timeout=1.0)

                if device:
                    await self._handle_usb_event(device)

                # Small delay to prevent CPU spinning
                await asyncio.sleep(0.1)

        except Exception as e:
            logger.error(f"Error in USB detection loop: {e}", exc_info=True)
            raise

    async def shutdown(self):
        """Cleanup USB monitoring resources"""
        if self.monitor:
            self.monitor = None

        if self.hash_db:
            self.hash_db.close()
            self.hash_db = None

        logger.info("USB detector shut down")

    async def _handle_usb_event(self, device: pyudev.Device):
        """
        Handle USB device event (add/remove)

        Args:
            device: pyudev Device object
        """
        try:
            action = device.action

            if action == 'add':
                await self._analyze_usb_device(device)
            elif action == 'remove':
                self._remove_device(device)

        except Exception as e:
            logger.error(f"Error handling USB event: {e}")

    async def _analyze_usb_device(self, device: pyudev.Device):
        """
        Analyze USB device for threats

        Args:
            device: pyudev Device object
        """
        # Extract device properties
        device_data = self._extract_device_info(device)

        # Check whitelist
        if self._is_whitelisted(device_data):
            logger.debug(f"Whitelisted device: {device_data.get('vid')} - {device_data.get('manufacturer')}")
            return

        # Store device
        device_id = device_data.get('device_path')
        self.known_devices[device_id] = device_data

        logger.info(f"Analyzing USB device: {device_data.get('product_name')} "
                   f"[{device_data.get('vid')}:{device_data.get('pid')}]")

        # Evaluate against rules
        await self.evaluate_event(device_data)

        # If device is storage, check filesystem
        if device_data.get('is_storage'):
            await self._analyze_storage_device(device, device_data)

    def _extract_device_info(self, device: pyudev.Device) -> Dict[str, Any]:
        """
        Extract relevant information from USB device

        Args:
            device: pyudev Device object

        Returns:
            Dictionary with device information
        """
        # Get device attributes
        vid = device.get('ID_VENDOR_ID', 'unknown')
        pid = device.get('ID_MODEL_ID', 'unknown')
        vendor = device.get('ID_VENDOR', 'unknown')
        model = device.get('ID_MODEL', 'unknown')
        serial = device.get('ID_SERIAL_SHORT', 'unknown')
        device_path = device.device_path

        # Determine if storage device
        is_storage = device.get('ID_BUS') == 'usb' and device.get('DEVTYPE') == 'disk'

        # Build device data
        device_info = {
            'vid': vid,
            'pid': pid,
            'vid_pid': f"{vid}:{pid}",
            'vendor': vendor,
            'manufacturer': vendor,
            'model': model,
            'product_name': model,
            'serial': serial,
            'device_path': device_path,
            'is_storage': is_storage,
            'device_class': device.get('ID_USB_DRIVER', 'unknown'),
            'timestamp': datetime.utcnow().isoformat(),
        }

        return device_info

    def _is_whitelisted(self, device_data: Dict[str, Any]) -> bool:
        """
        Check if device is whitelisted

        Args:
            device_data: Device information dictionary

        Returns:
            True if whitelisted, False otherwise
        """
        vid = device_data.get('vid', '')
        return vid in self.SYSTEM_WHITELIST

    def _remove_device(self, device: pyudev.Device):
        """Remove device from tracking"""
        device_path = device.device_path
        if device_path in self.known_devices:
            del self.known_devices[device_path]
            logger.debug(f"Device removed: {device_path}")

    async def _analyze_storage_device(self, device: pyudev.Device, device_data: Dict[str, Any]):
        """
        Analyze storage device for malicious files

        Args:
            device: pyudev Device object
            device_data: Device information
        """
        try:
            # Get mount point
            mount_point = self._get_mount_point(device)

            if not mount_point:
                logger.debug("Storage device not mounted yet")
                # Wait a bit for mount
                await asyncio.sleep(2.0)
                mount_point = self._get_mount_point(device)

            if not mount_point:
                logger.debug("Storage device still not mounted, skipping filesystem scan")
                return

            logger.info(f"Scanning storage device at: {mount_point}")

            # Get volume label
            volume_label = self._get_volume_label(device)
            if volume_label:
                # Check volume label against rules
                volume_data = {
                    **device_data,
                    'volume_label': volume_label
                }
                await self.evaluate_event(volume_data)

            # Scan files
            await self._scan_files(mount_point, device_data)

        except Exception as e:
            logger.error(f"Error analyzing storage device: {e}")

    def _get_mount_point(self, device: pyudev.Device) -> Optional[str]:
        """Get mount point for USB storage device"""
        try:
            # Try to get mount info from /proc/mounts
            with open('/proc/mounts', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and device.device_node in parts[0]:
                        return parts[1]
        except Exception as e:
            logger.debug(f"Error getting mount point: {e}")

        return None

    def _get_volume_label(self, device: pyudev.Device) -> Optional[str]:
        """Get volume label from device"""
        try:
            return device.get('ID_FS_LABEL', None)
        except:
            return None

    async def _scan_files(self, mount_point: str, device_data: Dict[str, Any]):
        """
        Scan files on USB storage device

        Args:
            mount_point: Mount point path
            device_data: Device information
        """
        mount_path = Path(mount_point)

        if not mount_path.exists():
            return

        # Scan for suspicious files
        for root, dirs, files in os.walk(mount_point):
            for filename in files:
                file_path = Path(root) / filename

                try:
                    # Skip large files (>100MB) for performance
                    file_size = file_path.stat().st_size
                    if file_size > 100 * 1024 * 1024:
                        continue

                    # Create file event data
                    file_data = {
                        **device_data,
                        'filename': filename,
                        'file_path': str(file_path),
                        'file_size': file_size,
                        'file_extension': file_path.suffix.lower()
                    }

                    # Check filename patterns
                    await self.evaluate_event(file_data)

                    # Hash-based detection for executables
                    if self._is_executable(filename):
                        await self._analyze_executable(file_path, file_data)

                except PermissionError:
                    logger.debug(f"Permission denied: {file_path}")
                except Exception as e:
                    logger.debug(f"Error scanning file {filename}: {e}")

    def _is_executable(self, filename: str) -> bool:
        """Check if file is executable"""
        exec_extensions = {'.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.app', '.sys', '.dll'}
        return Path(filename).suffix.lower() in exec_extensions

    async def _analyze_executable(self, file_path: Path, file_data: Dict[str, Any]):
        """
        Analyze executable file for malware

        Args:
            file_path: Path to executable
            file_data: File information dictionary
        """
        try:
            # Calculate hashes
            hashes = await self._calculate_hashes(file_path)

            if not hashes:
                return

            # Add hashes to event data
            file_data_with_hash = {
                **file_data,
                'sha256': hashes['sha256'],
                'md5': hashes['md5']
            }

            # Check against hash database
            if self.hash_db:
                malware_info = self._lookup_hash(hashes['sha256'], hashes['md5'])

                if malware_info:
                    logger.warning(f"⚠️ KNOWN MALWARE DETECTED: {malware_info['malware_name']}")

                    file_data_with_hash['malware_name'] = malware_info['malware_name']
                    file_data_with_hash['malware_family'] = malware_info.get('family', 'unknown')
                    file_data_with_hash['severity'] = malware_info.get('severity', 5)

            # Evaluate with hash data
            await self.evaluate_event(file_data_with_hash)

        except Exception as e:
            logger.debug(f"Error analyzing executable: {e}")

    async def _calculate_hashes(self, file_path: Path) -> Optional[Dict[str, str]]:
        """
        Calculate SHA256 and MD5 hashes

        Args:
            file_path: Path to file

        Returns:
            Dictionary with sha256 and md5 hashes
        """
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()

            # Read file in chunks
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
                    md5.update(chunk)

            return {
                'sha256': sha256.hexdigest(),
                'md5': md5.hexdigest()
            }

        except Exception as e:
            logger.debug(f"Error calculating hashes: {e}")
            return None

    def _lookup_hash(self, sha256: str, md5: str) -> Optional[Dict[str, Any]]:
        """
        Lookup hash in malware database

        Args:
            sha256: SHA256 hash
            md5: MD5 hash

        Returns:
            Malware information dictionary or None
        """
        if not self.hash_db:
            return None

        try:
            cursor = self.hash_db.cursor()

            # Try SHA256 first
            cursor.execute(
                'SELECT * FROM malware_hashes WHERE sha256_hash = ? LIMIT 1',
                (sha256,)
            )
            result = cursor.fetchone()

            if result:
                return dict(result)

            # Fallback to MD5
            cursor.execute(
                'SELECT * FROM malware_hashes WHERE md5_hash = ? LIMIT 1',
                (md5,)
            )
            result = cursor.fetchone()

            if result:
                return dict(result)

            return None

        except Exception as e:
            logger.error(f"Error looking up hash: {e}")
            return None

    def _get_rule_category(self) -> str:
        """Get rule category for this detector"""
        return 'usb'
