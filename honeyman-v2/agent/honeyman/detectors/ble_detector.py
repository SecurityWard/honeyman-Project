"""
BLE Detector - Detects Bluetooth Low Energy threats

Detects:
- Flipper Zero and custom firmware
- BLE spam attacks
- Manufacturer spoofing
- Apple Continuity abuse
- HID keyloggers
- ESP32 attack tools
- MAC randomization
- Conference badge spoofing
"""

import asyncio
import logging
import subprocess
import re
import time
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict
from .base_detector import BaseDetector

# Try to import bleak, fall back to bluetoothctl if unavailable
try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

logger = logging.getLogger(__name__)


class BleDetector(BaseDetector):
    """BLE threat detector using bleak or bluetoothctl"""

    def __init__(self, config: Dict[str, Any], rule_engine, transport):
        super().__init__(config, rule_engine, transport, 'ble')

        # Configuration
        self.scan_interval = config.get('ble', {}).get('scan_interval', 5.0)
        self.scan_duration = config.get('ble', {}).get('scan_duration', 3.0)
        self.use_bleak = BLEAK_AVAILABLE and config.get('ble', {}).get('use_bleak', True)
        self.track_services = config.get('ble', {}).get('track_services', True)
        self.rssi_threshold = config.get('ble', {}).get('rssi_threshold', -90)

        # Tracking state
        self.device_history: Dict[str, Dict[str, Any]] = {}
        self.device_appearances: Dict[str, List[datetime]] = defaultdict(list)
        self.device_name_changes: Dict[str, List[str]] = defaultdict(list)
        self.device_manufacturer_changes: Dict[str, List[str]] = defaultdict(list)
        self.service_enumeration_attempts: Dict[str, int] = defaultdict(int)

        # Whitelisting
        self.whitelist_macs: Set[str] = set(config.get('ble', {}).get('whitelist_macs', []))
        self.whitelist_names: Set[str] = set(config.get('ble', {}).get('whitelist_names', []))

        # Behavioral thresholds
        self.appearance_rate_window = 60  # seconds
        self.appearance_rate_threshold = 10  # appearances per window
        self.name_change_threshold = 3
        self.manufacturer_change_threshold = 2

        # Cleanup timer
        self.history_retention = 300  # 5 minutes
        self.last_cleanup = time.time()

    async def initialize(self):
        """Initialize BLE detector"""
        logger.info("Initializing BLE detector")

        if self.use_bleak:
            logger.info("Using bleak for BLE scanning")
        else:
            logger.info("Using bluetoothctl for BLE scanning")
            # Check if bluetoothctl is available
            if not await self._check_bluetoothctl():
                raise RuntimeError("bluetoothctl not available and bleak not installed")

        logger.info(f"BLE detector initialized (scan interval: {self.scan_interval}s)")

    async def detect(self):
        """Main detection loop"""
        logger.info("Starting BLE detection")

        while self.running:
            try:
                if self.use_bleak:
                    await self._scan_with_bleak()
                else:
                    await self._scan_with_bluetoothctl()

                # Periodic cleanup
                if time.time() - self.last_cleanup > self.history_retention:
                    self._cleanup_old_data()

                await asyncio.sleep(self.scan_interval)

            except Exception as e:
                logger.error(f"Error in BLE detection loop: {e}", exc_info=True)
                await asyncio.sleep(5)

    async def shutdown(self):
        """Cleanup on shutdown"""
        logger.info("Shutting down BLE detector")
        self.running = False
        self.device_history.clear()
        self.device_appearances.clear()

    async def _scan_with_bleak(self):
        """Scan for BLE devices using bleak"""
        try:
            devices = await BleakScanner.discover(
                timeout=self.scan_duration,
                return_adv=True
            )

            for device, adv_data in devices.values():
                await self._process_ble_device(device, adv_data)

        except Exception as e:
            logger.error(f"Bleak scan error: {e}")

    async def _scan_with_bluetoothctl(self):
        """Scan for BLE devices using bluetoothctl"""
        try:
            # Start scan
            await self._run_bluetoothctl_command("scan on")
            await asyncio.sleep(self.scan_duration)

            # Get devices
            output = await self._run_bluetoothctl_command("devices")

            # Stop scan
            await self._run_bluetoothctl_command("scan off")

            # Parse devices
            for line in output.split('\n'):
                if line.startswith('Device'):
                    await self._process_bluetoothctl_device(line)

        except Exception as e:
            logger.error(f"bluetoothctl scan error: {e}")

    async def _process_ble_device(self, device, adv_data):
        """Process a BLE device from bleak"""
        try:
            mac = device.address.upper()

            # Skip whitelisted devices
            if self._is_whitelisted(mac, device.name):
                return

            # Skip weak signals
            if adv_data.rssi < self.rssi_threshold:
                return

            # Extract device data
            device_data = {
                'mac_address': mac,
                'device_name': device.name or 'Unknown',
                'rssi': adv_data.rssi,
                'manufacturer_data': self._format_manufacturer_data(adv_data.manufacturer_data),
                'service_uuids': [str(uuid) for uuid in (adv_data.service_uuids or [])],
                'timestamp': datetime.utcnow().isoformat(),
                'detector_type': 'ble',
                'detection_method': 'bleak'
            }

            # Track device
            await self._track_device(device_data)

            # Add behavioral metrics
            device_data['appearance_rate'] = self._calculate_appearance_rate(mac)
            device_data['name_changes'] = len(self.device_name_changes[mac])
            device_data['manufacturer_changes'] = len(self.device_manufacturer_changes[mac])

            # Evaluate against rules
            await self.evaluate_event(device_data)

        except Exception as e:
            logger.error(f"Error processing BLE device: {e}")

    async def _process_bluetoothctl_device(self, line: str):
        """Process a device line from bluetoothctl"""
        try:
            # Parse: "Device AA:BB:CC:DD:EE:FF DeviceName"
            match = re.match(r'Device\s+([0-9A-F:]+)\s+(.*)', line)
            if not match:
                return

            mac = match.group(1).upper()
            name = match.group(2).strip()

            # Skip whitelisted
            if self._is_whitelisted(mac, name):
                return

            # Get more info about device
            info_output = await self._run_bluetoothctl_command(f"info {mac}")

            device_data = {
                'mac_address': mac,
                'device_name': name,
                'rssi': self._extract_rssi(info_output),
                'manufacturer_data': self._extract_manufacturer(info_output),
                'service_uuids': self._extract_services(info_output),
                'timestamp': datetime.utcnow().isoformat(),
                'detector_type': 'ble',
                'detection_method': 'bluetoothctl'
            }

            # Track device
            await self._track_device(device_data)

            # Add behavioral metrics
            device_data['appearance_rate'] = self._calculate_appearance_rate(mac)
            device_data['name_changes'] = len(self.device_name_changes[mac])
            device_data['manufacturer_changes'] = len(self.device_manufacturer_changes[mac])

            # Evaluate against rules
            await self.evaluate_event(device_data)

        except Exception as e:
            logger.error(f"Error processing bluetoothctl device: {e}")

    async def _track_device(self, device_data: Dict[str, Any]):
        """Track device appearances and changes"""
        mac = device_data['mac_address']
        name = device_data['device_name']
        manufacturer = device_data.get('manufacturer_data', '')

        now = datetime.utcnow()

        # Track appearance
        self.device_appearances[mac].append(now)

        # Track name changes
        if mac in self.device_history:
            old_name = self.device_history[mac].get('device_name')
            if old_name and old_name != name and name != 'Unknown':
                if name not in self.device_name_changes[mac]:
                    self.device_name_changes[mac].append(name)
                    logger.warning(f"BLE device {mac} changed name: {old_name} -> {name}")

        # Track manufacturer changes
        if mac in self.device_history:
            old_manufacturer = self.device_history[mac].get('manufacturer_data')
            if old_manufacturer and old_manufacturer != manufacturer and manufacturer:
                if manufacturer not in self.device_manufacturer_changes[mac]:
                    self.device_manufacturer_changes[mac].append(manufacturer)
                    logger.warning(f"BLE device {mac} changed manufacturer: {old_manufacturer} -> {manufacturer}")

        # Update history
        self.device_history[mac] = device_data

    def _calculate_appearance_rate(self, mac: str) -> float:
        """Calculate device appearance rate"""
        if mac not in self.device_appearances:
            return 0.0

        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.appearance_rate_window)

        # Count appearances in window
        recent_appearances = [
            ts for ts in self.device_appearances[mac]
            if ts > cutoff
        ]

        self.device_appearances[mac] = recent_appearances

        return len(recent_appearances) / (self.appearance_rate_window / 60)  # per minute

    def _format_manufacturer_data(self, manufacturer_data: Optional[Dict[int, bytes]]) -> str:
        """Format manufacturer data for analysis"""
        if not manufacturer_data:
            return ''

        formatted = []
        for company_id, data in manufacturer_data.items():
            hex_data = data.hex()
            formatted.append(f"{company_id:04x}:{hex_data}")

        return ','.join(formatted)

    def _extract_rssi(self, info_output: str) -> int:
        """Extract RSSI from bluetoothctl info output"""
        match = re.search(r'RSSI:\s*(-?\d+)', info_output)
        return int(match.group(1)) if match else -100

    def _extract_manufacturer(self, info_output: str) -> str:
        """Extract manufacturer data from bluetoothctl info output"""
        match = re.search(r'ManufacturerData.*?:\s*([0-9a-f]+)', info_output, re.IGNORECASE)
        return match.group(1) if match else ''

    def _extract_services(self, info_output: str) -> List[str]:
        """Extract service UUIDs from bluetoothctl info output"""
        services = []
        for line in info_output.split('\n'):
            if 'UUID:' in line:
                match = re.search(r'UUID:\s*([0-9a-f-]+)', line, re.IGNORECASE)
                if match:
                    services.append(match.group(1).lower())
        return services

    async def _run_bluetoothctl_command(self, command: str) -> str:
        """Run a bluetoothctl command"""
        try:
            process = await asyncio.create_subprocess_exec(
                'bluetoothctl',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=f"{command}\nexit\n".encode()),
                timeout=10.0
            )

            return stdout.decode('utf-8', errors='ignore')

        except Exception as e:
            logger.error(f"bluetoothctl command error: {e}")
            return ''

    async def _check_bluetoothctl(self) -> bool:
        """Check if bluetoothctl is available"""
        try:
            result = subprocess.run(
                ['which', 'bluetoothctl'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _is_whitelisted(self, mac: str, name: Optional[str]) -> bool:
        """Check if device is whitelisted"""
        if mac.upper() in self.whitelist_macs:
            return True

        if name and name in self.whitelist_names:
            return True

        return False

    def _cleanup_old_data(self):
        """Clean up old tracking data"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.history_retention)

        # Clean appearances
        for mac in list(self.device_appearances.keys()):
            self.device_appearances[mac] = [
                ts for ts in self.device_appearances[mac]
                if ts > cutoff
            ]
            if not self.device_appearances[mac]:
                del self.device_appearances[mac]

        # Clean history
        for mac in list(self.device_history.keys()):
            last_seen = datetime.fromisoformat(self.device_history[mac]['timestamp'])
            if last_seen < cutoff:
                del self.device_history[mac]
                if mac in self.device_name_changes:
                    del self.device_name_changes[mac]
                if mac in self.device_manufacturer_changes:
                    del self.device_manufacturer_changes[mac]

        self.last_cleanup = time.time()
        logger.debug(f"Cleaned up old BLE tracking data")

    def _get_rule_category(self) -> str:
        """Return rule category for this detector"""
        return 'ble'
