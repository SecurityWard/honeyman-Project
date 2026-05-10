#!/usr/bin/env python3
"""
Robust resync script that fetches all threats from Elasticsearch
and pushes them to the VPS dashboard
"""

import os
import sys
import time
import json
import requests
import logging
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/resync_all.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RobustDashboardResyncer:
    def __init__(self):
        # Configuration
        self.api_key = os.getenv('HOSTINGER_API_KEY')
        self.dashboard_url = os.getenv('DASHBOARD_URL', 'http://72.60.25.24:8080')
        
        if not self.api_key:
            raise ValueError("HOSTINGER_API_KEY environment variable not set")
        
        # Elasticsearch connection
        self.es = Elasticsearch(['http://localhost:9200'])
        
        # Batch configuration
        self.query_batch_size = 1000  # Fetch 1000 at a time from ES
        self.upload_batch_size = 20   # Upload 20 at a time to dashboard
        self.request_delay = 2         # Delay between uploads
        
        # Stats
        self.stats = {
            'total': 0,
            'uploaded': 0,
            'filtered': 0,
            'errors': 0,
            'start_time': datetime.utcnow()
        }
        
        logger.info("=" * 60)
        logger.info("🚀 Starting Robust Dashboard Resync")
        logger.info(f"📡 Dashboard URL: {self.dashboard_url}")
        logger.info("=" * 60)
    
    def sanitize_threat(self, threat):
        """Clean and prepare a single threat for upload"""
        # Essential fields only
        clean = {
            'timestamp': threat.get('timestamp'),
            'honeypot_id': threat.get('honeypot_id', 'honeyman-01'),
            'source': threat.get('source'),
            'detection_type': threat.get('detection_type'),
            'threat_score': float(threat.get('threat_score', 0)),
            'risk_level': threat.get('risk_level', 'medium'),
            'threats_detected': threat.get('threats_detected', []),
            'message': threat.get('message', ''),
        }
        
        # Add network info if present
        if 'network_info' in threat:
            clean['network_info'] = threat['network_info']
        if 'src_host' in threat:
            clean['src_host'] = threat['src_host']
        if 'src_port' in threat:
            clean['src_port'] = threat['src_port']
        
        # Remove None values
        return {k: v for k, v in clean.items() if v is not None}
    
    def upload_batch(self, threats):
        """Upload a batch of threats to the dashboard"""
        if not threats:
            return True
        
        try:
            # Sanitize threats
            sanitized = [self.sanitize_threat(t) for t in threats]
            
            # Prepare payload (no compression)
            payload = {
                'type': 'threats',
                'honeypot_id': 'honeyman-01',
                'compressed': False,
                'data': sanitized
            }
            
            headers = {
                'X-API-Key': self.api_key,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f'{self.dashboard_url}/api/honeypot/data',
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                self.stats['uploaded'] += len(sanitized)
                logger.info(f"✅ Uploaded {len(sanitized)} threats (Total: {self.stats['uploaded']})")
                return True
            elif response.status_code == 429:
                logger.warning("⚠️ Rate limit - waiting 30s")
                time.sleep(30)
                return False
            else:
                logger.error(f"❌ API error {response.status_code}: {response.text[:100]}")
                self.stats['errors'] += 1
                return False
                
        except Exception as e:
            logger.error(f"❌ Upload error: {e}")
            self.stats['errors'] += 1
            return False
    
    def fetch_threats_by_time_range(self, start_time, end_time):
        """Fetch threats for a specific time range"""
        try:
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": start_time.isoformat(),
                            "lt": end_time.isoformat()
                        }
                    }
                },
                "size": self.query_batch_size,
                "sort": [{"timestamp": {"order": "asc"}}]
            }
            
            # Use search_after for pagination
            threats = []
            last_sort = None
            
            while True:
                if last_sort:
                    query["search_after"] = last_sort
                
                response = self.es.search(index="honeypot-logs-new", body=query)
                hits = response['hits']['hits']
                
                if not hits:
                    break
                
                for hit in hits:
                    threat = hit['_source']
                    # Basic filtering
                    if threat.get('threat_score', 0) >= 0.2:
                        threats.append(threat)
                    else:
                        self.stats['filtered'] += 1
                
                # Get last sort value for pagination
                last_sort = hits[-1]['sort']
                
                # Break if we got fewer results than requested
                if len(hits) < self.query_batch_size:
                    break
            
            return threats
            
        except Exception as e:
            logger.error(f"❌ Error fetching threats: {e}")
            return []
    
    def run(self):
        """Main resync process using time-based chunking"""
        try:
            # Get time range of data
            response = self.es.search(
                index="honeypot-logs-new",
                body={
                    "aggs": {
                        "min_time": {"min": {"field": "timestamp"}},
                        "max_time": {"max": {"field": "timestamp"}}
                    },
                    "size": 0
                }
            )
            
            min_timestamp = response['aggregations']['min_time']['value_as_string']
            max_timestamp = response['aggregations']['max_time']['value_as_string']
            total_docs = response['hits']['total']['value']
            
            logger.info(f"📊 Total documents: {total_docs}")
            logger.info(f"📅 Date range: {min_timestamp} to {max_timestamp}")
            
            self.stats['total'] = total_docs
            
            # Process in daily chunks
            start_date = datetime.fromisoformat(min_timestamp.replace('Z', '+00:00'))
            end_date = datetime.fromisoformat(max_timestamp.replace('Z', '+00:00'))
            
            current_date = start_date
            upload_buffer = []
            
            while current_date < end_date:
                next_date = current_date + timedelta(days=1)
                
                logger.info(f"📅 Processing: {current_date.date()}")
                
                # Fetch threats for this day
                threats = self.fetch_threats_by_time_range(current_date, next_date)
                
                if threats:
                    logger.info(f"   Found {len(threats)} threats")
                    
                    # Add to buffer
                    upload_buffer.extend(threats)
                    
                    # Upload when buffer is full
                    while len(upload_buffer) >= self.upload_batch_size:
                        batch = upload_buffer[:self.upload_batch_size]
                        success = self.upload_batch(batch)
                        
                        if success:
                            upload_buffer = upload_buffer[self.upload_batch_size:]
                            time.sleep(self.request_delay)
                        else:
                            # Retry after delay
                            time.sleep(10)
                
                # Progress update
                progress_pct = (self.stats['uploaded'] / total_docs) * 100 if total_docs > 0 else 0
                logger.info(f"📈 Progress: {self.stats['uploaded']}/{total_docs} ({progress_pct:.1f}%)")
                
                current_date = next_date
            
            # Upload remaining threats
            while upload_buffer:
                batch = upload_buffer[:self.upload_batch_size]
                success = self.upload_batch(batch)
                
                if success:
                    upload_buffer = upload_buffer[self.upload_batch_size:]
                    time.sleep(self.request_delay)
                else:
                    time.sleep(10)
            
            # Final summary
            duration = datetime.utcnow() - self.stats['start_time']
            logger.info("=" * 60)
            logger.info("✅ RESYNC COMPLETED")
            logger.info(f"📊 Total processed: {self.stats['uploaded'] + self.stats['filtered']}")
            logger.info(f"✅ Uploaded: {self.stats['uploaded']}")
            logger.info(f"🔍 Filtered: {self.stats['filtered']}")
            logger.info(f"❌ Errors: {self.stats['errors']}")
            logger.info(f"⏱️ Duration: {duration}")
            logger.info("=" * 60)
            
        except KeyboardInterrupt:
            logger.info("🛑 Resync interrupted")
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            raise

if __name__ == "__main__":
    resyncer = RobustDashboardResyncer()
    resyncer.run()