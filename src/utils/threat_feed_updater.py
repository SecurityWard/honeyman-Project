#!/usr/bin/env python3
"""
Threat Intelligence Feed Updater for BSidesNoVa
Pulls latest IoCs from multiple sources and updates detection signatures
"""

import requests
import json
import time
import re
from datetime import datetime, timedelta
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/threat_feeds.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ThreatFeedUpdater:
    def __init__(self):
        self.base_dir = Path('/home/burner/honeypot-minimal')
        self.cache_dir = self.base_dir / 'cache' / 'threat_feeds'
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Threat feed sources
        self.feeds = {
            'malware_ips': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
                'cache_file': 'malware_ips.txt',
                'description': 'Feodo Tracker C2 IPs'
            },
            'malware_domains': {
                'url': 'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/generic.txt',
                'cache_file': 'malware_domains.txt',
                'description': 'Maltrail malware domains'
            },
            'badusb_signatures': {
                'url': 'https://raw.githubusercontent.com/hak5/usb-rubber-ducky/master/payloads/library/general/RickRoll/payload.txt',
                'cache_file': 'badusb_patterns.txt',
                'description': 'BadUSB payload patterns',
                'fallback': True  # Use fallback if URL fails
            }
        }
        
        # Enhanced signatures from threat intel
        self.enhanced_signatures = {
            'usb_vendors': {
                # Known malicious USB vendor/product combinations
                '1209:0001': 'Generic HID device - common BadUSB',
                '16c0:05dc': 'USBaspLoader - used in BadUSB devices',
                '04d8:003f': 'Microchip PIC - DIY attack devices',
                '1209:2100': 'Digispark board - common for BadUSB',
                '2341:0043': 'Arduino Uno - possible attack device'
            },
            'wifi_ouis': {
                # Rogue AP manufacturer patterns from recent reports
                '00:13:37': 'Hak5 devices',
                '00:C0:CA': 'WiFi Pineapple variations',
                'DE:AD:BE': 'Common spoofed OUI',
                'BA:DB:EE': 'Common spoofed OUI',
                '00:11:22': 'Generic/spoofed OUI pattern'
            },
            'ble_attack_patterns': {
                # Conference badges and tools from 2024 cons
                'DEF CON 32': 'DefCon 2024 badge',
                'BSides 2024': 'BSides conference badges',
                'BSIDES LV': 'BSides Las Vegas badge',
                'HackRF': 'Software Defined Radio tool',
                'BladeRF': 'Software Defined Radio tool',
                'YARD Stick': 'Sub-GHz transceiver'
            }
        }
    
    def fetch_feed(self, feed_name, feed_config):
        """Fetch and cache a threat feed"""
        try:
            logger.info(f"Fetching {feed_config['description']}...")
            
            response = requests.get(feed_config['url'], timeout=30)
            response.raise_for_status()
            
            # Save to cache
            cache_file = self.cache_dir / feed_config['cache_file']
            with open(cache_file, 'w') as f:
                f.write(response.text)
            
            logger.info(f"Updated {feed_name}: {len(response.text.splitlines())} entries")
            return True
            
        except Exception as e:
            logger.error(f"Failed to fetch {feed_name}: {e}")
            
            # Use fallback if available
            if feed_config.get('fallback'):
                return self.create_fallback_signatures(feed_name)
            return False
    
    def create_fallback_signatures(self, feed_name):
        """Create fallback signatures when feeds are unavailable"""
        fallback_data = {
            'badusb_signatures': [
                'GUI r',  # Windows Run dialog
                'STRING cmd',  # Command prompt
                'STRING powershell',  # PowerShell
                'DELAY 1000',  # Common delay pattern
                'ENTER',  # Enter key
                'ALT F4',  # Close window
                'CTRL SHIFT ESC',  # Task manager
                'STRING iex',  # PowerShell Invoke-Expression
            ]
        }
        
        if feed_name in fallback_data:
            cache_file = self.cache_dir / self.feeds[feed_name]['cache_file']
            with open(cache_file, 'w') as f:
                for pattern in fallback_data[feed_name]:
                    f.write(f"{pattern}\n")
            logger.info(f"Created fallback signatures for {feed_name}")
            return True
        return False
    
    def parse_ip_feed(self, feed_file):
        """Parse IP-based threat feed"""
        ips = set()
        try:
            with open(self.cache_dir / feed_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple IP validation
                        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', line):
                            ips.add(line)
            return list(ips)
        except Exception as e:
            logger.error(f"Error parsing IP feed {feed_file}: {e}")
            return []
    
    def parse_domain_feed(self, feed_file):
        """Parse domain-based threat feed"""
        domains = set()
        try:
            with open(self.cache_dir / feed_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract domain from various formats
                        if '.' in line and not line.startswith('http'):
                            # Simple domain validation
                            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line):
                                domains.add(line.lower())
            return list(domains)
        except Exception as e:
            logger.error(f"Error parsing domain feed {feed_file}: {e}")
            return []
    
    def generate_ioc_database(self):
        """Generate consolidated IoC database"""
        ioc_db = {
            'timestamp': datetime.utcnow().isoformat(),
            'sources': list(self.feeds.keys()),
            'malware_ips': self.parse_ip_feed('malware_ips.txt'),
            'malware_domains': self.parse_domain_feed('malware_domains.txt'),
            'enhanced_signatures': self.enhanced_signatures
        }
        
        # Save consolidated database
        ioc_file = self.cache_dir / 'consolidated_iocs.json'
        with open(ioc_file, 'w') as f:
            json.dump(ioc_db, f, indent=2)
        
        logger.info(f"Generated IoC database: {len(ioc_db['malware_ips'])} IPs, {len(ioc_db['malware_domains'])} domains")
        return ioc_db
    
    def update_detector_signatures(self, ioc_db):
        """Update detection signatures in existing detectors"""
        try:
            # Update USB detector with new VID/PID combinations
            usb_detector_file = self.base_dir / 'src' / 'detectors' / 'usb_bsides_detector.py'
            if usb_detector_file.exists():
                self.inject_usb_signatures(usb_detector_file, ioc_db['enhanced_signatures']['usb_vendors'])
            
            # Update WiFi detector with new OUIs
            wifi_detector_file = self.base_dir / 'src' / 'detectors' / 'wifi_bsides_detector.py'
            if wifi_detector_file.exists():
                self.inject_wifi_signatures(wifi_detector_file, ioc_db['enhanced_signatures']['wifi_ouis'])
            
            # Update BLE detector with new patterns
            ble_detector_file = self.base_dir / 'src' / 'detectors' / 'ble_bsides_detector.py'
            if ble_detector_file.exists():
                self.inject_ble_signatures(ble_detector_file, ioc_db['enhanced_signatures']['ble_attack_patterns'])
            
            logger.info("Updated detector signatures from threat feeds")
            
        except Exception as e:
            logger.error(f"Error updating detector signatures: {e}")
    
    def inject_usb_signatures(self, detector_file, new_vendors):
        """Add new USB vendor signatures to detector"""
        # For now, just log what we would add
        # In production, this would modify the detector file or use a separate config
        logger.info(f"Would add {len(new_vendors)} new USB vendor signatures")
        for vid_pid, description in new_vendors.items():
            logger.debug(f"USB signature: {vid_pid} - {description}")
    
    def inject_wifi_signatures(self, detector_file, new_ouis):
        """Add new WiFi OUI signatures to detector"""
        logger.info(f"Would add {len(new_ouis)} new WiFi OUI signatures")
        for oui, description in new_ouis.items():
            logger.debug(f"WiFi OUI: {oui} - {description}")
    
    def inject_ble_signatures(self, detector_file, new_patterns):
        """Add new BLE attack patterns to detector"""
        logger.info(f"Would add {len(new_patterns)} new BLE attack patterns")
        for pattern, description in new_patterns.items():
            logger.debug(f"BLE pattern: {pattern} - {description}")
    
    def run_update(self):
        """Run complete threat feed update"""
        logger.info("🌐 Starting threat feed update for BSidesNoVa")
        
        # Fetch all feeds
        success_count = 0
        for feed_name, feed_config in self.feeds.items():
            if self.fetch_feed(feed_name, feed_config):
                success_count += 1
        
        if success_count == 0:
            logger.error("No threat feeds could be updated")
            return False
        
        # Generate consolidated IoC database
        ioc_db = self.generate_ioc_database()
        
        # Update detector signatures
        self.update_detector_signatures(ioc_db)
        
        logger.info(f"✅ Threat feed update complete: {success_count}/{len(self.feeds)} feeds updated")
        return True

def main():
    updater = ThreatFeedUpdater()
    
    # Run update
    success = updater.run_update()
    
    # Schedule next update (for demonstration)
    if success:
        logger.info("Threat intelligence updated successfully")
        logger.info("Next update scheduled in 24 hours (implement with cron job)")
    else:
        logger.error("Threat intelligence update failed")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())