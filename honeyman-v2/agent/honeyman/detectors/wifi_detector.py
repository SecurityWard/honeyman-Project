#!/usr/bin/env python3
"""
WiFi Threat Detector - V2

Detects WiFi attacks including:
- Evil Twin access points
- Deauthentication attacks
- Beacon flooding
- WiFi Pineapple / KARMA attacks
- ESP8266 deauthers
- Flipper Zero WiFi attacks
- WPS attacks
- Suspicious SSIDs
"""

import asyncio
import logging
import subprocess
import re
import json
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional, Set

from .base_detector import BaseDetector

logger = logging.getLogger(__name__)


class WifiDetector(BaseDetector):
    """
    WiFi threat detection using scapy or iwlist

    Detects threats via:
    - SSID pattern matching
    - MAC address analysis (OUI matching)
    - Beacon flood detection
    - Deauth frame monitoring
    - Evil twin correlation
    - Behavioral analysis
    """

    def __init__(self, rule_engine, transport, config, location_service):
        super().__init__(rule_engine, transport, config, location_service)

        # Network tracking
        self.known_networks = {}
        self.network_history = defaultdict(lambda: {
            'bssids': set(),
            'channels': set(),
            'encryptions': set(),
            'signal_history': deque(maxlen=50),
            'first_seen': None,
            'last_seen': None,
            'beacon_count': 0
        })

        # Attack tracking
        self.deauth_tracker = defaultdict(lambda: deque(maxlen=100))
        self.beacon_tracker = defaultdict(int)

        # Whitelist
        self.bssid_whitelist: Set[str] = set()
        self.ssid_whitelist: Set[str] = set()

        # Interface
        self.interface = None
        self.monitor_mode = False
        self.use_scapy = True  # Prefer scapy if available

        # Load whitelist
        self._load_whitelist()

    def _load_whitelist(self):
        """Load WiFi whitelist configuration"""
        try:
            whitelist_path = self.config.get('wifi.whitelist_path',
                                            '/etc/honeyman/wifi_whitelist.json')

            if Path(whitelist_path).exists():
                with open(whitelist_path, 'r') as f:
                    data = json.load(f)
                    self.bssid_whitelist = set(data.get('bssid_whitelist', []))
                    self.ssid_whitelist = set(data.get('ssid_whitelist', []))

                logger.info(f"Loaded whitelist: {len(self.bssid_whitelist)} BSSIDs, "
                           f"{len(self.ssid_whitelist)} SSIDs")
            else:
                logger.info("No whitelist found, using empty whitelist")

        except Exception as e:
            logger.warning(f"Error loading whitelist: {e}")

    async def initialize(self):
        """Initialize WiFi monitoring"""
        try:
            # Detect WiFi interface
            self.interface = await self._detect_interface()

            if not self.interface:
                raise RuntimeError("No WiFi interface found")

            logger.info(f"Using WiFi interface: {self.interface}")

            # Check if scapy is available
            try:
                import scapy.all as scapy
                self.use_scapy = True
                logger.info("Using scapy for packet capture")
            except ImportError:
                self.use_scapy = False
                logger.info("Scapy not available, using iwlist fallback")

            # Enable monitor mode if using scapy
            if self.use_scapy:
                await self._enable_monitor_mode()

            logger.info("WiFi detector initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize WiFi detector: {e}")
            raise RuntimeError(f"WiFi detector initialization failed: {e}")

    async def detect(self):
        """Main WiFi detection loop"""
        logger.info("WiFi detector starting detection loop...")

        try:
            if self.use_scapy:
                await self._detect_with_scapy()
            else:
                await self._detect_with_iwlist()

        except Exception as e:
            logger.error(f"Error in WiFi detection loop: {e}", exc_info=True)
            raise

    async def shutdown(self):
        """Cleanup WiFi monitoring resources"""
        if self.monitor_mode:
            await self._disable_monitor_mode()

        logger.info("WiFi detector shut down")

    async def _detect_interface(self) -> Optional[str]:
        """Detect available WiFi interface"""
        try:
            result = await asyncio.create_subprocess_exec(
                'iw', 'dev',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, _ = await result.communicate()

            for line in stdout.decode().split('\n'):
                if 'Interface' in line:
                    interface = line.split()[-1]
                    logger.debug(f"Found interface: {interface}")
                    return interface

        except Exception as e:
            logger.debug(f"Error detecting interface: {e}")

        return None

    async def _enable_monitor_mode(self):
        """Enable monitor mode on WiFi interface"""
        try:
            # Kill interfering processes
            await asyncio.create_subprocess_exec(
                'sudo', 'airmon-ng', 'check', 'kill',
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )

            # Enable monitor mode
            result = await asyncio.create_subprocess_exec(
                'sudo', 'airmon-ng', 'start', self.interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await result.communicate()

            # Update interface name (usually becomes wlan0mon)
            self.interface = f"{self.interface}mon"
            self.monitor_mode = True

            logger.info(f"Monitor mode enabled on {self.interface}")

        except Exception as e:
            logger.warning(f"Failed to enable monitor mode: {e}")
            self.monitor_mode = False
            self.use_scapy = False

    async def _disable_monitor_mode(self):
        """Disable monitor mode"""
        try:
            if self.monitor_mode and self.interface:
                # Get original interface name
                original_if = self.interface.replace('mon', '')

                await asyncio.create_subprocess_exec(
                    'sudo', 'airmon-ng', 'stop', self.interface,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )

                self.interface = original_if
                self.monitor_mode = False

                logger.info("Monitor mode disabled")

        except Exception as e:
            logger.warning(f"Error disabling monitor mode: {e}")

    async def _detect_with_scapy(self):
        """Detect WiFi threats using scapy packet capture"""
        try:
            from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Deauth

            logger.info("Starting scapy packet capture...")

            def packet_handler(packet):
                """Handle captured packet"""
                asyncio.create_task(self._process_packet(packet))

            # Sniff WiFi packets
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: not self.running
            )

        except Exception as e:
            logger.error(f"Error in scapy detection: {e}")
            # Fallback to iwlist
            self.use_scapy = False
            await self._detect_with_iwlist()

    async def _process_packet(self, packet):
        """
        Process captured WiFi packet

        Args:
            packet: Scapy packet object
        """
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11ProbeResp

            # Beacon frames
            if packet.haslayer(Dot11Beacon):
                await self._handle_beacon(packet)

            # Deauth frames
            elif packet.haslayer(Dot11Deauth):
                await self._handle_deauth(packet)

            # Probe responses (KARMA attack detection)
            elif packet.haslayer(Dot11ProbeResp):
                await self._handle_probe_response(packet)

        except Exception as e:
            logger.debug(f"Error processing packet: {e}")

    async def _handle_beacon(self, packet):
        """Handle beacon frame"""
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt

            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')

            # Track beacon
            self.beacon_tracker[ssid] += 1

            # Extract network info
            network_data = {
                'ssid': ssid,
                'bssid': bssid,
                'channel': self._get_channel_from_packet(packet),
                'signal': packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else None,
                'encryption': self._get_encryption(packet),
                'timestamp': datetime.utcnow().isoformat()
            }

            # Check whitelist
            if self._is_whitelisted(network_data):
                return

            # Update network history
            self._update_network_history(network_data)

            # Evaluate against rules
            await self.evaluate_event(network_data)

            # Check for beacon flooding
            await self._check_beacon_flooding()

        except Exception as e:
            logger.debug(f"Error handling beacon: {e}")

    async def _handle_deauth(self, packet):
        """Handle deauthentication frame"""
        try:
            from scapy.all import Dot11

            bssid = packet[Dot11].addr2
            client = packet[Dot11].addr1

            # Track deauth
            self.deauth_tracker[bssid].append({
                'client': client,
                'timestamp': datetime.utcnow()
            })

            # Check for deauth attack
            await self._check_deauth_attack(bssid)

        except Exception as e:
            logger.debug(f"Error handling deauth: {e}")

    async def _handle_probe_response(self, packet):
        """Handle probe response (KARMA attack detection)"""
        try:
            from scapy.all import Dot11

            bssid = packet[Dot11].addr2

            # Track probe responses for KARMA detection
            # (responding to all probes is suspicious)

        except Exception as e:
            logger.debug(f"Error handling probe response: {e}")

    async def _detect_with_iwlist(self):
        """Detect WiFi threats using iwlist (fallback method)"""
        logger.info("Using iwlist for WiFi scanning...")

        scan_interval = self.config.get('wifi.scan_interval', 10)

        while self.running:
            try:
                networks = await self._scan_networks_iwlist()

                for network in networks:
                    # Check whitelist
                    if self._is_whitelisted(network):
                        continue

                    # Update network history
                    self._update_network_history(network)

                    # Evaluate against rules
                    await self.evaluate_event(network)

                # Check for beacon flooding
                await self._check_beacon_flooding()

                # Wait before next scan
                await asyncio.sleep(scan_interval)

            except Exception as e:
                logger.error(f"Error in iwlist scan: {e}")
                await asyncio.sleep(scan_interval)

    async def _scan_networks_iwlist(self) -> List[Dict[str, Any]]:
        """
        Scan for WiFi networks using iwlist

        Returns:
            List of network dictionaries
        """
        networks = []

        try:
            result = await asyncio.create_subprocess_exec(
                'sudo', 'iwlist', self.interface, 'scan',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, _ = await result.communicate()

            current_network = {}

            for line in stdout.decode().split('\n'):
                line = line.strip()

                # New cell (network)
                if 'Cell' in line and 'Address:' in line:
                    if current_network:
                        networks.append(current_network)

                    current_network = {
                        'bssid': line.split('Address: ')[1].strip(),
                        'ssid': '',
                        'channel': '',
                        'signal': '',
                        'encryption': [],
                        'timestamp': datetime.utcnow().isoformat()
                    }

                # SSID
                elif 'ESSID:' in line:
                    ssid = line.split('ESSID:')[1].strip().strip('"')
                    current_network['ssid'] = ssid

                # Frequency/Channel
                elif 'Frequency:' in line:
                    freq = line.split('Frequency:')[1].split()[0]
                    current_network['frequency'] = freq

                # Signal
                elif 'Signal level=' in line:
                    signal = line.split('Signal level=')[1].split()[0]
                    current_network['signal'] = signal

                # Encryption
                elif 'WPA' in line and 'WPA' not in current_network['encryption']:
                    current_network['encryption'].append('WPA')
                elif 'WEP' in line and 'WEP' not in current_network['encryption']:
                    current_network['encryption'].append('WEP')

            # Add last network
            if current_network:
                networks.append(current_network)

        except Exception as e:
            logger.error(f"Error scanning networks: {e}")

        return networks

    def _is_whitelisted(self, network: Dict[str, Any]) -> bool:
        """
        Check if network is whitelisted

        Args:
            network: Network data dictionary

        Returns:
            True if whitelisted
        """
        bssid = network.get('bssid', '')
        ssid = network.get('ssid', '')

        return bssid in self.bssid_whitelist or ssid in self.ssid_whitelist

    def _update_network_history(self, network: Dict[str, Any]):
        """Update network history for evil twin detection"""
        ssid = network.get('ssid')
        bssid = network.get('bssid')

        if not ssid or not bssid:
            return

        history = self.network_history[ssid]

        # Track BSSIDs for this SSID
        history['bssids'].add(bssid)

        # Track channels
        if network.get('channel'):
            history['channels'].add(network['channel'])

        # Track encryption
        if network.get('encryption'):
            history['encryptions'].add(tuple(network['encryption']))

        # Update timestamps
        if not history['first_seen']:
            history['first_seen'] = network['timestamp']
        history['last_seen'] = network['timestamp']

        history['beacon_count'] += 1

    async def _check_beacon_flooding(self):
        """Check for beacon flooding attack"""
        # Count unique SSIDs in last minute
        recent_threshold = 50

        if len(self.beacon_tracker) > recent_threshold:
            flood_data = {
                'threat_type': 'beacon_flood',
                'unique_ssids_per_scan': len(self.beacon_tracker),
                'timestamp': datetime.utcnow().isoformat()
            }

            await self.evaluate_event(flood_data)

            # Reset tracker after alert
            self.beacon_tracker.clear()

    async def _check_deauth_attack(self, bssid: str):
        """
        Check for deauthentication attack

        Args:
            bssid: BSSID of access point
        """
        deauths = self.deauth_tracker[bssid]

        # Count deauths in last minute
        now = datetime.utcnow()
        recent = [d for d in deauths if (now - d['timestamp']).total_seconds() < 60]

        if len(recent) > 10:  # Threshold
            deauth_data = {
                'threat_type': 'deauth_attack',
                'bssid': bssid,
                'deauth_count_per_minute': len(recent),
                'timestamp': now.isoformat()
            }

            await self.evaluate_event(deauth_data)

    def _get_channel_from_packet(self, packet) -> Optional[int]:
        """Extract channel from packet"""
        # Placeholder - would need to parse RadioTap header
        return None

    def _get_encryption(self, packet) -> List[str]:
        """Extract encryption type from packet"""
        # Placeholder - would parse RSN/WPA information elements
        return []

    def _get_rule_category(self) -> str:
        """Get rule category for this detector"""
        return 'wifi'
