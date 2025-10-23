#!/usr/bin/env python3
"""
Push ALL DEFCON events including USB threats - Fixed deduplication
"""

import os
import time
import json
import hashlib
import requests
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from elasticsearch import Elasticsearch

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/complete_defcon_push.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CompleteDefconPusher:
    def __init__(self):
        self.api_key = "Yx4tWEr1ExbOA1HbYEIcz9D7uzk9-znoEPwdoLV0VY0"
        self.dashboard_url = 'http://72.60.25.24:8080'
        self.es = Elasticsearch(['http://localhost:9200'])
        
        # Less aggressive deduplication
        self.threat_signatures = set()
        
        self.stats = {
            'total_events': 0,
            'unique_events': 0,
            'duplicates': 0,
            'batches_sent': 0,
            'failed_batches': 0,
            'by_source': defaultdict(int),
            'by_detection_type': defaultdict(int)
        }
    
    def create_minimal_signature(self, threat):
        """Minimal deduplication - only remove exact duplicates"""
        # For USB events, use timestamp + source + first threat detected
        timestamp = threat.get('timestamp', '')
        source = threat.get('source', '')
        detection_type = threat.get('detection_type', '')
        first_threat = threat.get('threats_detected', [''])[0] if threat.get('threats_detected') else ''
        
        # Create signature
        signature_data = {
            'timestamp': timestamp,
            'source': source,
            'detection': detection_type,
            'first_threat': first_threat
        }
        
        signature_string = json.dumps(signature_data, sort_keys=True)
        return hashlib.md5(signature_string.encode()).hexdigest()
    
    def fetch_and_push_by_source(self, source_pattern):
        """Fetch and push events for a specific source"""
        logger.info(f"🔍 Processing {source_pattern} events...")
        
        query = {
            "size": 1000,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": "2025-08-07T00:00:00", "lte": "2025-08-10T23:59:59"}}},
                        {"wildcard": {"source": source_pattern}},
                        {"exists": {"field": "threat_score"}}
                    ],
                    "must_not": [
                        {"term": {"log_type.keyword": "system_status"}}
                    ]
                }
            },
            "sort": [{"timestamp": "asc"}]
        }
        
        all_events = []
        try:
            # Use scroll to get all events for this source
            response = self.es.search(index="honeypot-logs-new", body=query, scroll='5m')
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            all_events.extend(hits)
            
            # Continue scrolling
            while hits:
                response = self.es.scroll(scroll_id=scroll_id, scroll='5m')
                scroll_id = response['_scroll_id'] 
                hits = response['hits']['hits']
                all_events.extend(hits)
                
                if len(all_events) % 10000 == 0:
                    logger.info(f"  📦 Fetched {len(all_events)} {source_pattern} events...")
            
            # Clear scroll
            self.es.clear_scroll(scroll_id=scroll_id)
            
            logger.info(f"✅ Total {source_pattern} events: {len(all_events):,}")
            
            # Minimal deduplication
            unique_events = []
            for event in all_events:
                threat = event['_source']
                
                # Skip very low scores but keep more events
                if threat.get('threat_score', 0) < 0.1:
                    continue
                
                signature = self.create_minimal_signature(threat)
                
                if signature not in self.threat_signatures:
                    self.threat_signatures.add(signature)
                    unique_events.append(threat)
                    self.stats['unique_events'] += 1
                    self.stats['by_source'][threat.get('source', 'unknown')] += 1
                    self.stats['by_detection_type'][threat.get('detection_type', 'unknown')] += 1
                else:
                    self.stats['duplicates'] += 1
                
                self.stats['total_events'] += 1
            
            logger.info(f"📊 {source_pattern}: {len(unique_events):,} unique from {len(all_events):,} total")
            
            # Send events in batches
            self.send_events_in_batches(unique_events, source_pattern)
            
        except Exception as e:
            logger.error(f"❌ Error processing {source_pattern}: {e}")
    
    def send_events_in_batches(self, events, source_name):
        """Send events in smaller batches"""
        if not events:
            return
            
        batch_size = 20  # Smaller batches for reliability
        total_batches = (len(events) + batch_size - 1) // batch_size
        
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            batch_num = i // batch_size + 1
            
            payload = {
                'type': 'threats',
                'honeypot_id': 'honeyman-defcon-fixed',
                'source_type': source_name,
                'data': batch
            }
            
            try:
                response = requests.post(
                    f'{self.dashboard_url}/api/honeypot/data',
                    json=payload,
                    headers={'X-API-Key': self.api_key},
                    timeout=60
                )
                
                if response.status_code == 200:
                    logger.info(f"✅ {source_name} batch {batch_num}/{total_batches}: {len(batch)} events")
                    self.stats['batches_sent'] += 1
                else:
                    logger.error(f"❌ {source_name} batch {batch_num} failed: {response.status_code}")
                    self.stats['failed_batches'] += 1
                    
                # Rate limiting
                time.sleep(20)  # Faster processing
                
            except Exception as e:
                logger.error(f"❌ {source_name} batch {batch_num} error: {e}")
                self.stats['failed_batches'] += 1
                time.sleep(30)
    
    def push_all_by_sources(self):
        """Push all events grouped by source type"""
        logger.info("="*80)
        logger.info("🚀 COMPLETE DEFCON PUSH - BY SOURCE TYPE")
        logger.info("="*80)
        
        # Process each source type separately to ensure nothing is missed
        sources_to_process = [
            "*usb*",         # All USB-related events
            "*wifi*",        # WiFi events  
            "*ble*",         # Bluetooth events
            "*airdrop*",     # AirDrop events
            "*canary*"       # Honeypot events
        ]
        
        for source in sources_to_process:
            self.fetch_and_push_by_source(source)
            logger.info(f"✅ Completed {source}")
            time.sleep(10)  # Brief pause between sources
        
        # Print final statistics
        logger.info("="*80)
        logger.info("📊 COMPLETE PUSH STATISTICS")
        logger.info("="*80)
        logger.info(f"Total events processed: {self.stats['total_events']:,}")
        logger.info(f"Unique events sent: {self.stats['unique_events']:,}")
        logger.info(f"Duplicates removed: {self.stats['duplicates']:,}")
        logger.info(f"Batches sent: {self.stats['batches_sent']}")
        logger.info(f"Failed batches: {self.stats['failed_batches']}")
        logger.info("")
        logger.info("By Source:")
        for source, count in sorted(self.stats['by_source'].items()):
            logger.info(f"  {source}: {count:,}")
        logger.info("")
        logger.info("By Detection Type:")
        for det_type, count in sorted(self.stats['by_detection_type'].items()):
            logger.info(f"  {det_type}: {count:,}")
        logger.info("="*80)

if __name__ == "__main__":
    pusher = CompleteDefconPusher()
    pusher.push_all_by_sources()