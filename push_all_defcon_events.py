#!/usr/bin/env python3
"""
Push ALL unique DEFCON events (Aug 7-10, 2025) to VPS enhanced dashboard
Processes ~80k events with intelligent deduplication
"""

import os
import time
import json
import gzip
import hashlib
import requests
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from elasticsearch import Elasticsearch
from io import BytesIO

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/defcon_push_complete.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DefconCompletePusher:
    def __init__(self):
        self.api_key = "Yx4tWEr1ExbOA1HbYEIcz9D7uzk9-znoEPwdoLV0VY0"
        self.dashboard_url = 'http://72.60.25.24:8080'
        
        # Elasticsearch connection
        self.es = Elasticsearch(['http://localhost:9200'])
        
        # Enhanced deduplication tracking
        self.threat_signatures = defaultdict(list)
        self.time_windows = defaultdict(set)
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'unique_events': 0,
            'duplicates': 0,
            'batches_sent': 0,
            'failed_batches': 0,
            'by_threat_score': defaultdict(int),
            'by_detection_type': defaultdict(int),
            'by_day': defaultdict(int)
        }
    
    def create_enhanced_threat_signature(self, threat):
        """Create enhanced signature for better deduplication"""
        # Extract key identifying characteristics
        detection_type = threat.get('detection_type', 'unknown')
        threat_score = round(threat.get('threat_score', 0), 1)
        timestamp = threat.get('timestamp', '')
        
        # Create time window (5-minute buckets)
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_bucket = dt.replace(minute=(dt.minute // 5) * 5, second=0, microsecond=0)
            except:
                time_bucket = datetime.now()
        else:
            time_bucket = datetime.now()
        
        # Different signature strategies by detection type
        if detection_type == 'suspicious_network':
            # For network threats, group by BSSID and threat type
            network_info = threat.get('network_info', {})
            bssid = network_info.get('bssid', '')
            ssid = network_info.get('ssid', '')
            threats_detected = sorted(threat.get('threats_detected', []))
            
            signature_data = {
                'type': 'network',
                'bssid': bssid,
                'ssid': ssid,
                'threats': threats_detected,
                'score': threat_score,
                'time_bucket': time_bucket.isoformat()
            }
        
        elif 'usb' in detection_type.lower():
            # For USB threats, group by device characteristics
            device_info = threat.get('device_info', {})
            vendor_id = device_info.get('vendor_id', '')
            product_id = device_info.get('product_id', '')
            threats_detected = sorted(threat.get('threats_detected', []))
            
            signature_data = {
                'type': 'usb',
                'vendor_id': vendor_id,
                'product_id': product_id,
                'threats': threats_detected,
                'score': threat_score,
                'time_bucket': time_bucket.isoformat()
            }
        
        elif 'ble' in detection_type.lower():
            # For BLE threats, group by device MAC and service
            device_info = threat.get('device_info', {})
            mac_address = device_info.get('mac_address', '')
            device_name = device_info.get('device_name', '')
            threats_detected = sorted(threat.get('threats_detected', []))
            
            signature_data = {
                'type': 'ble',
                'mac': mac_address,
                'name': device_name,
                'threats': threats_detected,
                'score': threat_score,
                'time_bucket': time_bucket.isoformat()
            }
        
        else:
            # Generic deduplication for other types
            signature_data = {
                'type': detection_type,
                'score': threat_score,
                'threats': sorted(threat.get('threats_detected', [])),
                'source': threat.get('source', ''),
                'time_bucket': time_bucket.isoformat()
            }
        
        # Create hash
        signature_string = json.dumps(signature_data, sort_keys=True)
        return hashlib.sha256(signature_string.encode()).hexdigest()
    
    def fetch_all_defcon_events(self):
        """Fetch ALL events from DEFCON period using scroll API"""
        start_date = "2025-08-07T00:00:00"
        end_date = "2025-08-10T23:59:59"
        
        logger.info(f"🔍 Fetching ALL events from {start_date} to {end_date}")
        
        # Initial search with scroll
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": start_date, "lte": end_date}}},
                        {"exists": {"field": "threat_score"}}
                    ],
                    "must_not": [
                        {"term": {"log_type.keyword": "system_status"}}
                    ]
                }
            },
            "sort": [{"timestamp": "asc"}],
            "_source": ["timestamp", "detection_type", "threat_score", "threats_detected", 
                       "source", "network_info", "device_info", "log_type", "message"]
        }
        
        all_events = []
        
        try:
            # Initialize scroll
            response = self.es.search(
                index="honeypot-logs-new", 
                body=query, 
                scroll='5m',
                size=1000
            )
            
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            all_events.extend(hits)
            
            logger.info(f"📦 Initial batch: {len(hits)} events")
            
            # Continue scrolling
            while hits:
                response = self.es.scroll(scroll_id=scroll_id, scroll='5m')
                scroll_id = response['_scroll_id']
                hits = response['hits']['hits']
                all_events.extend(hits)
                
                if len(all_events) % 5000 == 0:
                    logger.info(f"📦 Fetched {len(all_events)} events so far...")
            
            # Clear scroll
            self.es.clear_scroll(scroll_id=scroll_id)
            
            logger.info(f"✅ Total events fetched: {len(all_events)}")
            return all_events
            
        except Exception as e:
            logger.error(f"❌ Error fetching events: {e}")
            return []
    
    def deduplicate_events(self, events):
        """Enhanced deduplication with time-window grouping"""
        logger.info("🔄 Starting enhanced deduplication...")
        
        # Group events by signature
        signature_groups = defaultdict(list)
        
        for event in events:
            threat = event['_source']
            
            # Skip very low-score threats
            threat_score = threat.get('threat_score', 0)
            if threat_score < 0.2:
                continue
            
            signature = self.create_enhanced_threat_signature(threat)
            signature_groups[signature].append(threat)
            
            self.stats['total_events'] += 1
            self.stats['by_threat_score'][threat_score] += 1
            
            detection_type = threat.get('detection_type', 'unknown')
            self.stats['by_detection_type'][detection_type] += 1
            
            # Track by day
            timestamp = threat.get('timestamp', '')
            if timestamp:
                day = timestamp[:10]
                self.stats['by_day'][day] += 1
        
        # Select best representative from each group
        unique_events = []
        for signature, threat_group in signature_groups.items():
            if len(threat_group) == 1:
                unique_events.append(threat_group[0])
                self.stats['unique_events'] += 1
            else:
                # Select threat with highest score, most recent timestamp
                best_threat = max(threat_group, key=lambda t: (
                    t.get('threat_score', 0),
                    t.get('timestamp', '')
                ))
                unique_events.append(best_threat)
                self.stats['unique_events'] += 1
                self.stats['duplicates'] += len(threat_group) - 1
        
        logger.info(f"✅ Deduplication complete: {len(unique_events)} unique from {len(events)} total")
        return unique_events
    
    def send_batch(self, threats, batch_num, total_batches):
        """Send a batch of threats to the dashboard"""
        if not threats:
            return True
        
        payload = {
            'type': 'threats',
            'honeypot_id': 'honeyman-defcon-complete',
            'batch_info': {
                'batch': batch_num,
                'total_batches': total_batches,
                'events_in_batch': len(threats)
            },
            'data': threats
        }
        
        json_data = json.dumps(payload)
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': self.api_key
        }
        
        try:
            response = requests.post(
                f'{self.dashboard_url}/api/honeypot/data',
                data=json_data,
                headers=headers,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"✅ Batch {batch_num}/{total_batches}: {len(threats)} threats sent successfully")
                self.stats['batches_sent'] += 1
                return True
            else:
                logger.error(f"❌ Batch {batch_num} failed: {response.status_code} - {response.text}")
                self.stats['failed_batches'] += 1
                return False
                
        except Exception as e:
            logger.error(f"❌ API error for batch {batch_num}: {e}")
            self.stats['failed_batches'] += 1
            return False
    
    def verify_dashboard_update(self):
        """Check if dashboard stats updated"""
        try:
            response = requests.get(f'{self.dashboard_url}/api/threats/stats', timeout=10)
            if response.status_code == 200:
                stats = response.json()
                logger.info(f"📊 Dashboard now shows: {stats.get('total_threats', 0)} total threats")
                return stats
        except Exception as e:
            logger.warning(f"Could not verify dashboard: {e}")
        return None
    
    def push_all_defcon_events(self):
        """Main function to push all DEFCON events"""
        logger.info("=" * 80)
        logger.info("🚀 DEFCON COMPLETE EVENT PUSH STARTING")
        logger.info("=" * 80)
        
        # Get initial dashboard stats
        initial_stats = self.verify_dashboard_update()
        initial_count = initial_stats.get('total_threats', 0) if initial_stats else 0
        
        # Fetch all events
        logger.info("📥 Fetching all DEFCON events from Elasticsearch...")
        events = self.fetch_all_defcon_events()
        
        if not events:
            logger.warning("❌ No events found in DEFCON date range")
            return
        
        # Deduplicate
        logger.info("🔄 Performing enhanced deduplication...")
        unique_threats = self.deduplicate_events(events)
        
        if not unique_threats:
            logger.warning("❌ No unique threats after deduplication")
            return
        
        # Send in batches of 25 (smaller batches for reliability)
        batch_size = 25
        total_batches = (len(unique_threats) + batch_size - 1) // batch_size
        
        logger.info(f"📤 Sending {len(unique_threats)} unique threats in {total_batches} batches")
        
        successful_pushes = 0
        for i in range(0, len(unique_threats), batch_size):
            batch = unique_threats[i:i+batch_size]
            batch_num = i // batch_size + 1
            
            logger.info(f"📦 Processing batch {batch_num}/{total_batches}...")
            
            if self.send_batch(batch, batch_num, total_batches):
                successful_pushes += len(batch)
                
                # Rate limiting between batches
                if batch_num < total_batches:
                    logger.info("⏱️  Waiting 30 seconds for rate limiting...")
                    time.sleep(30)
            else:
                logger.error(f"❌ Batch {batch_num} failed, waiting 60 seconds before continuing...")
                time.sleep(60)
        
        # Final verification
        logger.info("🔍 Verifying dashboard update...")
        time.sleep(5)  # Give dashboard time to process
        final_stats = self.verify_dashboard_update()
        final_count = final_stats.get('total_threats', 0) if final_stats else 0
        
        # Print comprehensive statistics
        logger.info("=" * 80)
        logger.info("📊 DEFCON PUSH COMPLETE - FINAL STATISTICS")
        logger.info("=" * 80)
        logger.info(f"📈 Events processed: {self.stats['total_events']:,}")
        logger.info(f"🎯 Unique events: {self.stats['unique_events']:,}")
        logger.info(f"🗑️  Duplicates removed: {self.stats['duplicates']:,}")
        logger.info(f"📤 Batches sent: {self.stats['batches_sent']}")
        logger.info(f"❌ Failed batches: {self.stats['failed_batches']}")
        logger.info(f"📊 Events pushed successfully: {successful_pushes:,}")
        logger.info("")
        logger.info("📊 By Threat Score:")
        for score, count in sorted(self.stats['by_threat_score'].items()):
            logger.info(f"   {score}: {count:,} events")
        logger.info("")
        logger.info("📊 By Detection Type:")
        for det_type, count in sorted(self.stats['by_detection_type'].items()):
            logger.info(f"   {det_type}: {count:,} events")
        logger.info("")
        logger.info("📊 By Day:")
        for day, count in sorted(self.stats['by_day'].items()):
            logger.info(f"   {day}: {count:,} events")
        logger.info("")
        logger.info(f"📊 Dashboard Threats Before: {initial_count:,}")
        logger.info(f"📊 Dashboard Threats After: {final_count:,}")
        logger.info(f"📊 Net Increase: {final_count - initial_count:,}")
        logger.info("=" * 80)
        
        # Success confirmation
        if self.stats['failed_batches'] == 0:
            logger.info("🎉 ALL DEFCON EVENTS SUCCESSFULLY PUSHED TO DASHBOARD!")
        else:
            logger.warning(f"⚠️  Push completed with {self.stats['failed_batches']} failed batches")
        
        logger.info(f"🌐 View results at: {self.dashboard_url}/enhanced_dashboard.html")

if __name__ == "__main__":
    pusher = DefconCompletePusher()
    pusher.push_all_defcon_events()