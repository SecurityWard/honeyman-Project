#!/usr/bin/env python3
"""
Balanced DEFCON event push - Interleaves all detection sources
"""

import os
import time
import json
import hashlib
import requests
import logging
from datetime import datetime
from collections import defaultdict
from elasticsearch import Elasticsearch
import random

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/balanced_defcon_push.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BalancedDefconPusher:
    def __init__(self):
        self.api_key = "Yx4tWEr1ExbOA1HbYEIcz9D7uzk9-znoEPwdoLV0VY0"
        self.dashboard_url = 'http://72.60.25.24:8080'
        self.es = Elasticsearch(['http://localhost:9200'])
        
        self.stats = {
            'total_events': 0,
            'batches_sent': 0,
            'failed_batches': 0,
            'by_source': defaultdict(int)
        }
        
        # Store all events by source
        self.events_by_source = {}
    
    def fetch_all_events(self):
        """Fetch all DEFCON events grouped by source"""
        logger.info("="*80)
        logger.info("🚀 FETCHING ALL DEFCON EVENTS")
        logger.info("="*80)
        
        sources = [
            "usb_keystroke_monitor",
            "wifi_threat_detector", 
            "enhanced_usb_monitor",
            "opencanary",
            "usb_filesystem_monitor"
        ]
        
        for source in sources:
            logger.info(f"📥 Fetching {source} events...")
            
            query = {
                "size": 1000,
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"timestamp": {"gte": "2025-08-07T00:00:00", "lte": "2025-08-10T23:59:59"}}},
                            {"term": {"source": source}},
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
                # Use scroll to get all events
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
                
                # Clear scroll
                self.es.clear_scroll(scroll_id=scroll_id)
                
                # Extract source data
                source_events = [event['_source'] for event in all_events]
                self.events_by_source[source] = source_events
                
                logger.info(f"✅ {source}: {len(source_events):,} events")
                self.stats['by_source'][source] = len(source_events)
                self.stats['total_events'] += len(source_events)
                
            except Exception as e:
                logger.error(f"❌ Error fetching {source}: {e}")
                self.events_by_source[source] = []
    
    def create_balanced_batches(self, batch_size=50):
        """Create batches with proportional representation of all sources"""
        logger.info("🔄 Creating balanced batches...")
        
        # Calculate proportions based on actual counts
        total = sum(len(events) for events in self.events_by_source.values())
        if total == 0:
            logger.error("No events to process!")
            return []
        
        # Create indices for each source
        source_indices = {source: 0 for source in self.events_by_source.keys()}
        
        batches = []
        batch_count = 0
        
        while any(source_indices[src] < len(self.events_by_source[src]) 
                 for src in self.events_by_source.keys()):
            
            batch = []
            
            # Calculate how many events from each source for this batch
            for source, events in self.events_by_source.items():
                if source_indices[source] >= len(events):
                    continue
                    
                # Proportional representation
                proportion = len(events) / total
                count_in_batch = max(1, int(batch_size * proportion))
                
                # Get events for this batch
                start_idx = source_indices[source]
                end_idx = min(start_idx + count_in_batch, len(events))
                
                batch.extend(events[start_idx:end_idx])
                source_indices[source] = end_idx
            
            if batch:
                # Shuffle to mix sources within batch
                random.shuffle(batch)
                batches.append(batch)
                batch_count += 1
        
        logger.info(f"✅ Created {batch_count} balanced batches")
        return batches
    
    def send_balanced_batches(self, batches):
        """Send balanced batches to dashboard"""
        logger.info(f"📤 Sending {len(batches)} balanced batches...")
        
        for i, batch in enumerate(batches, 1):
            # Count sources in this batch for logging
            source_counts = defaultdict(int)
            for event in batch:
                source_counts[event.get('source', 'unknown')] += 1
            
            sources_str = ', '.join([f"{src}:{cnt}" for src, cnt in source_counts.items()])
            
            payload = {
                'type': 'threats',
                'honeypot_id': 'honeyman-defcon-balanced',
                'source_type': 'mixed',
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
                    logger.info(f"✅ Batch {i}/{len(batches)}: {len(batch)} events [{sources_str}]")
                    self.stats['batches_sent'] += 1
                else:
                    logger.error(f"❌ Batch {i} failed: {response.status_code}")
                    self.stats['failed_batches'] += 1
                
                # Rate limiting
                time.sleep(10)  # 10 seconds between batches
                
            except Exception as e:
                logger.error(f"❌ Batch {i} error: {e}")
                self.stats['failed_batches'] += 1
                time.sleep(15)
        
        logger.info("="*80)
        logger.info("📊 PUSH COMPLETE")
        logger.info("="*80)
        logger.info(f"Total events: {self.stats['total_events']:,}")
        logger.info(f"Batches sent: {self.stats['batches_sent']}")
        logger.info(f"Failed batches: {self.stats['failed_batches']}")
        logger.info("\nBy Source:")
        for source, count in sorted(self.stats['by_source'].items()):
            percentage = (count / self.stats['total_events'] * 100) if self.stats['total_events'] > 0 else 0
            logger.info(f"  {source}: {count:,} ({percentage:.1f}%)")
    
    def run(self):
        """Main execution"""
        # Fetch all events
        self.fetch_all_events()
        
        if self.stats['total_events'] == 0:
            logger.error("No events found to push!")
            return
        
        # Create balanced batches
        batches = self.create_balanced_batches(batch_size=50)
        
        # Send batches
        self.send_balanced_batches(batches)

if __name__ == "__main__":
    pusher = BalancedDefconPusher()
    pusher.run()