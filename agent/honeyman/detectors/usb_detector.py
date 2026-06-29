#!/usr/bin/env python3
"""
USB Threat Detector.

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
import time
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
                                     '/var/lib/honeyman/malware_hashes.db')

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
        """Initialize USB monitoring via pyudev.

        Subscribes to TWO subsystems on the same Monitor:

          - 'usb'   — USB-device-level events that carry VID/PID, vendor,
                     product, manufacturer, ID_USB_INTERFACES, etc. Used
                     by the VID/PID and product-name rules
                     (rubber_ducky, bash_bunny, omg_cable, …).
          - 'block' — block-device events for /dev/sd[a-z][0-9] and the
                     parent disks. Partition events here carry ID_FS_LABEL
                     populated by udev's blkid probe, so the
                     suspicious_volume_label rule (STARKILLER, PWNED,
                     BADUSB, etc.) sees them without needing a mount.

        Subscribing to 'usb' only — what we used to do — meant block
        events never reached us at all, so any rule that fields on
        `volume_label` or `filename` was dead from the start.
        """
        try:
            self.context = pyudev.Context()
            self.monitor = pyudev.Monitor.from_netlink(self.context)
            self.monitor.filter_by('usb')
            self.monitor.filter_by('block')
            logger.info("USB detector initialized (subsystems: usb, block)")

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
        Analyze USB device for threats.

        Three event shapes worth handling differently:
          - usb_device   parent USB-level events (carry VID/PID/manufacturer)
          - disk         block-device events (DEVTYPE='disk', is_storage)
          - partition    block-partition events (DEVTYPE='partition' — these
                         carry ID_FS_LABEL even when the partition isn't
                         mounted, so they're how we catch STARKILLER-style
                         volume-label rules without needing usbmount)

        Args:
            device: pyudev Device object
        """
        devtype = device.get('DEVTYPE') or ''

        # Partition events carry the filesystem label as soon as udev probes
        # them, mount or no mount. Handle them on a dedicated path so we can
        # walk up to the parent USB device for VID/PID context and fire the
        # volume-label rules.
        if devtype == 'partition':
            await self._analyze_partition(device)
            return

        # Extract device properties for non-partition events
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

    async def _analyze_partition(self, device: pyudev.Device):
        """Run rule evaluation against a USB partition's filesystem label
        and (if mountable) scan its files against the malware-hash DB.

        We subscribe to the `block` subsystem in addition to `usb` so we
        see partition events — that's the only place ID_FS_LABEL lives,
        and it's populated by udev's blkid probe the moment the partition
        appears (no mount required for the label check).

        Scope: this handler must only fire for USB-backed block devices.
        Without that check we'd also react to the Pi's own SD card and
        any internal storage. We use `find_parent('usb', 'usb_device')` —
        if it returns None, the partition isn't on the USB bus and we
        skip it.

        For the file-hash scan we mount the partition ourselves rather
        than rely on usbmount (which was removed from Debian Bookworm's
        repos). Read-only, nodev, noexec, nosuid, into /run/honeyman/usb-N
        with N picked to avoid collisions.
        """
        parent = device.find_parent('usb', 'usb_device')
        if parent is None:
            # Not a USB-backed partition — Pi SD card, NVMe, etc. Ignore.
            return

        volume_label = device.get('ID_FS_LABEL') or device.get('ID_FS_LABEL_ENC')

        device_data: Dict[str, Any] = {
            'timestamp':     datetime.utcnow().isoformat(),
            'device_path':   device.device_path,
            'device_node':   device.device_node,
            'fs_type':       device.get('ID_FS_TYPE'),
            'fs_uuid':       device.get('ID_FS_UUID'),
            'is_storage':    True,
            'vid':           parent.get('ID_VENDOR_ID', 'unknown'),
            'pid':           parent.get('ID_MODEL_ID', 'unknown'),
            'vid_pid':       f"{parent.get('ID_VENDOR_ID', 'unknown')}:{parent.get('ID_MODEL_ID', 'unknown')}",
            'vendor':        parent.get('ID_VENDOR', 'unknown'),
            'manufacturer':  parent.get('ID_VENDOR', 'unknown'),
            'model':         parent.get('ID_MODEL', 'unknown'),
            'product_name':  parent.get('ID_MODEL', 'unknown'),
            'serial':        parent.get('ID_SERIAL_SHORT', 'unknown'),
            'usb_interfaces': parent.get('ID_USB_INTERFACES'),
        }
        if volume_label:
            device_data['volume_label'] = volume_label
            device_data['filename'] = volume_label  # alias for file_pattern rules

        logger.info(
            f"USB partition: dev={device.device_node} label={volume_label!r} "
            f"vid_pid={device_data['vid_pid']} vendor={device_data['vendor']}"
        )

        # 1) Volume-label / metadata-based rule eval (no mount required).
        if volume_label:
            await self.evaluate_event(device_data)

        # 2) File-hash scan — needs the partition mounted. The agent does
        #    the mount itself: read-only, on a private path, unmounted after.
        await self._scan_partition_files(device, device_data)

    async def _scan_partition_files(
        self,
        device: pyudev.Device,
        device_data: Dict[str, Any],
    ):
        """Mount a USB partition read-only, walk it, and unmount.

        We do this in-process rather than relying on usbmount because (a)
        usbmount was removed from Debian Bookworm's repos and (b) the
        agent already runs as root, so the mount syscall is cheap and the
        sandboxing concerns that motivated usbmount don't apply here.
        """
        node = device.device_node
        if not node:
            return

        # Already mounted somewhere by an external auto-mounter? Just use that.
        existing = self._get_mount_point_for_node(node)
        if existing:
            logger.info(f"Partition {node} already mounted at {existing}; scanning")
            await self._scan_files(existing, device_data)
            return

        fstype = device.get('ID_FS_TYPE')
        if not fstype:
            logger.debug(f"No ID_FS_TYPE on {node}; skipping file scan")
            return

        mount_root = Path('/run/honeyman/usb')
        try:
            mount_root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(f"Could not create mount root {mount_root}: {exc}")
            return

        # Pick a per-event mount path so concurrent inserts don't collide.
        mount_path = mount_root / f"{Path(node).name}-{os.getpid()}-{int(time.time())}"
        try:
            mount_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(f"Could not create mount path {mount_path}: {exc}")
            return

        # ro,nodev,noexec,nosuid — we're reading files to hash them, never
        # executing them. uid=0,gid=0 keeps FAT/exfat from rejecting root.
        cmd = [
            "mount", "-t", fstype, "-o",
            "ro,nodev,noexec,nosuid,sync,uid=0,gid=0",
            node, str(mount_path),
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
        except asyncio.TimeoutError:
            logger.warning(f"mount {node} timed out after 15s; abandoning")
            return
        except Exception as exc:
            logger.warning(f"mount {node} failed: {exc}")
            return

        if proc.returncode != 0:
            err = (stderr or b"").decode("utf-8", "replace").strip()
            logger.warning(
                f"mount {node} returned {proc.returncode}: {err or '(no stderr)'}"
            )
            try:
                mount_path.rmdir()
            except OSError:
                pass
            return

        try:
            logger.info(f"Mounted {node} at {mount_path} (ro); scanning")
            await self._scan_files(str(mount_path), device_data)
        finally:
            await self._unmount(mount_path)

    async def _unmount(self, mount_path: Path) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                "umount", str(mount_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except Exception as exc:
            logger.warning(f"umount {mount_path} failed: {exc}")
        try:
            mount_path.rmdir()
        except OSError:
            pass

    @staticmethod
    def _get_mount_point_for_node(device_node: str) -> Optional[str]:
        """Look up the current mount point for a /dev path in /proc/mounts."""
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == device_node:
                        return parts[1]
        except OSError:
            pass
        return None

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
            # ID_USB_INTERFACES looks like ":030101:080650:" — colon-separated
            # interface-class hex codes (HID Keyboard = 0301xx, Mass Storage
            # = 0806xx, etc.). The "exposes both HID and MSC" BadUSB rule
            # regexes against this.
            'usb_interfaces': device.get('ID_USB_INTERFACES', ''),
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
        Analyze a disk-level USB storage device.

        The volume-label check is normally handled on the partition event
        (see _analyze_partition), but some firmwares put ID_FS_LABEL on the
        disk itself, so we check here too as a safety net.

        The file-hash scan requires the partition to be mounted. usbmount or
        similar auto-mount tooling is expected; without it this method
        returns gracefully without scanning, but the partition-level
        volume-label rule still runs.

        Args:
            device: pyudev Device object
            device_data: Device information
        """
        try:
            # Disk-level label as a safety net — fire even without mount.
            volume_label = self._get_volume_label(device)
            if volume_label:
                await self.evaluate_event({
                    **device_data,
                    'volume_label': volume_label,
                    'filename': volume_label,
                })

            # File-hash scan requires a mount point.
            mount_point = self._get_mount_point(device)
            if not mount_point:
                await asyncio.sleep(2.0)
                mount_point = self._get_mount_point(device)
            if not mount_point:
                logger.info(
                    "Storage device %s not mounted; skipping filesystem scan. "
                    "Install usbmount on the sensor for auto-mount.",
                    device.device_node or device.device_path,
                )
                return

            logger.info(f"Scanning storage device at: {mount_point}")
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
