#!/usr/bin/env python3
"""
Resync all historical data from Elasticsearch to VPS Dashboard
This script will fetch all threat data from Elasticsearch and push it to the dashboard
"""

import os
import sys
import time
import json
import gzip
import hashlib
import requests
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/resync_dashboard.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DashboardResyncer:
    def __init__(self):
        # Configuration
        self.api_key = os.getenv('HOSTINGER_API_KEY')
        self.dashboard_url = os.getenv('DASHBOARD_URL', 'http://72.60.25.24:8080')
        
        if not self.api_key:
            raise ValueError("HOSTINGER_API_KEY environment variable not set")
        
        # Elasticsearch connection
        self.es = Elasticsearch(['http://localhost:9200'])
        
        # Batch configuration
        self.batch_size = 500  # Process 500 documents at a time
        self.upload_batch_size = 10  # Upload 10 threats at a time (reduced to avoid API issues)
        self.request_delay = 3  # Delay between API calls (seconds)
        
        # Stats tracking
        self.stats = {
            'total_documents': 0,
            'uploaded': 0,
            'filtered': 0,
            'errors': 0,
            'start_time': datetime.utcnow()
        }
        
        logger.info(f"🚀 Starting Dashboard Resync")
        logger.info(f"📡 Dashboard URL: {self.dashboard_url}")
        logger.info(f"📊 Batch size: {self.batch_size} documents")
    
    def compress_data(self, data, data_type="threats"):
        """Don't compress data - dashboard API seems to have issues with it"""
        return {
            'type': data_type,
            'honeypot_id': 'honeyman-01',
            'compressed': False,
            'data': data
        }
    
    def sanitize_threat_data(self, threats):
        """Sanitize and prepare threat data for upload"""
        sanitized = []
        for threat in threats:
            # Create clean copy with essential fields
            clean_threat = {
                'timestamp': threat.get('timestamp'),
                'honeypot_id': threat.get('honeypot_id', 'honeyman-01'),
                'source': threat.get('source'),
                'log_type': threat.get('log_type'),
                'threat_type': threat.get('threat_type'),
                'detection_type': threat.get('detection_type'),
                'threat_score': float(threat.get('threat_score', 0)),
                'risk_level': threat.get('risk_level'),
                'threats_detected': threat.get('threats_detected', []),
                'message': threat.get('message'),
                'src_host': threat.get('src_host'),
                'src_port': threat.get('src_port'),
                'dst_host': threat.get('dst_host'),
                'dst_port': threat.get('dst_port'),
                'network_info': threat.get('network_info', {}),
                'device_info': threat.get('device_info', {}),
                'service_info': threat.get('service_info', {}),
                'attack_info': threat.get('attack_info', {})
            }
            
            # Remove None values to reduce payload size
            clean_threat = {k: v for k, v in clean_threat.items() if v is not None}
            
            # Ensure required fields
            if 'timestamp' in clean_threat and 'source' in clean_threat:
                sanitized.append(clean_threat)
        
        return sanitized
    
    def filter_threat(self, threat):
        """Basic filtering to remove noise"""
        # Check for minimum threat score
        threat_score = threat.get('threat_score', 0)
        if threat_score < 0.2:  # Lower threshold for historical data
            return False
        
        # Skip internal/localhost connections
        src_host = threat.get('src_host', '')
        if src_host in ['127.0.0.1', 'localhost', '::1']:
            return False
        
        return True
    
    def upload_batch(self, threats):
        """Upload a batch of threats to the dashboard"""
        if not threats:
            return True
        
        try:
            # Sanitize and compress
            sanitized = self.sanitize_threat_data(threats)
            if not sanitized:
                logger.warning("No valid threats after sanitization")
                return True
            
            payload = self.compress_data(sanitized, "threats")
            
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
                logger.info(f"✅ Uploaded batch of {len(sanitized)} threats")
                return True
            elif response.status_code == 429:
                logger.warning(f"⚠️ Rate limit hit - waiting 30 seconds")
                time.sleep(30)
                return False
            else:
                logger.error(f"❌ API error: {response.status_code} - {response.text[:100]}")
                self.stats['errors'] += 1
                return False
                
        except Exception as e:
            logger.error(f"❌ Upload error: {e}")
            self.stats['errors'] += 1
            return False
    
    def fetch_all_threats(self):
        """Fetch all threats from Elasticsearch using scroll API"""
        try:
            # Initial query
            query = {
                "query": {
                    "match_all": {}
                },
                "sort": [{"timestamp": {"order": "asc"}}],
                "size": self.batch_size
            }
            
            # Initialize scroll
            response = self.es.search(
                index="honeypot-logs-new",
                body=query,
                scroll='2m'  # Keep scroll context alive for 2 minutes
            )
            
            scroll_id = response['_scroll_id']
            total_hits = response['hits']['total']['value']
            
            logger.info(f"📊 Found {total_hits} total documents to process")
            self.stats['total_documents'] = total_hits
            
            # Process first batch
            hits = response['hits']['hits']
            batch_to_upload = []
            
            while hits:
                # Process current batch
                for hit in hits:
                    threat = hit['_source']
                    
                    # Apply filtering
                    if self.filter_threat(threat):
                        batch_to_upload.append(threat)
                    else:
                        self.stats['filtered'] += 1
                    
                    # Upload when batch is full
                    if len(batch_to_upload) >= self.upload_batch_size:
                        success = self.upload_batch(batch_to_upload)
                        if success:
                            batch_to_upload = []
                            time.sleep(self.request_delay)  # Rate limiting
                        else:
                            logger.warning("Upload failed, retrying...")
                            time.sleep(10)
                
                # Progress update
                processed = self.stats['uploaded'] + self.stats['filtered'] + self.stats['errors']
                if processed % 1000 == 0:
                    pct = (processed / total_hits) * 100
                    logger.info(f"📈 Progress: {processed}/{total_hits} ({pct:.1f}%)")
                    logger.info(f"   Uploaded: {self.stats['uploaded']}, Filtered: {self.stats['filtered']}, Errors: {self.stats['errors']}")
                
                # Get next batch
                response = self.es.scroll(scroll_id=scroll_id, scroll='2m')
                scroll_id = response['_scroll_id']
                hits = response['hits']['hits']
            
            # Upload remaining threats
            if batch_to_upload:
                self.upload_batch(batch_to_upload)
            
            # Clear scroll
            self.es.clear_scroll(scroll_id=scroll_id)
            
            logger.info("✅ Completed fetching all threats")
            
        except Exception as e:
            logger.error(f"❌ Error fetching threats: {e}")
    
    def upload_system_status(self):
        """Upload current system status to dashboard"""
        try:
            # Get Elasticsearch health
            es_health = self.es.cluster.health()
            
            status = {
                'timestamp': datetime.utcnow().isoformat(),
                'honeypot_id': 'honeyman-01',
                'elasticsearch_status': es_health.get('status', 'unknown'),
                'total_documents': self.stats['total_documents'],
                'synced_documents': self.stats['uploaded'],
                'filtered_documents': self.stats['filtered'],
                'sync_errors': self.stats['errors'],
                'sync_duration': str(datetime.utcnow() - self.stats['start_time']),
                'services': {
                    'elasticsearch': es_health.get('status', 'unknown'),
                    'resync_tool': 'completed'
                }
            }
            
            payload = self.compress_data([status], "status")
            
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
                logger.info("✅ System status uploaded")
            else:
                logger.error(f"❌ Failed to upload status: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Error uploading status: {e}")
    
    def run(self):
        """Main resync process"""
        logger.info("=" * 60)
        logger.info("🔄 STARTING DASHBOARD DATA RESYNC")
        logger.info("=" * 60)
        
        try:
            # Fetch and upload all threats
            self.fetch_all_threats()
            
            # Upload final status
            self.upload_system_status()
            
            # Print summary
            duration = datetime.utcnow() - self.stats['start_time']
            logger.info("=" * 60)
            logger.info("✅ RESYNC COMPLETED")
            logger.info(f"📊 Total documents: {self.stats['total_documents']}")
            logger.info(f"✅ Uploaded: {self.stats['uploaded']}")
            logger.info(f"🔍 Filtered: {self.stats['filtered']}")
            logger.info(f"❌ Errors: {self.stats['errors']}")
            logger.info(f"⏱️ Duration: {duration}")
            logger.info("=" * 60)
            
        except KeyboardInterrupt:
            logger.info("🛑 Resync interrupted by user")
        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            raise

if __name__ == "__main__":
    resyncer = DashboardResyncer()
    resyncer.run()