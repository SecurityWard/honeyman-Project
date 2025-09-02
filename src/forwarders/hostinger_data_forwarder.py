#!/usr/bin/env python3
"""
Improved Hostinger Data Forwarder with Filtering and Rate Limiting
Reduces noise and implements intelligent threat aggregation
"""

import os
import time
import json
import gzip
import hashlib
import requests
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, NotFoundError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/home/burner/honeypot-minimal/logs/hostinger_forwarder_filtered.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FilteredDataForwarder:
    def __init__(self):
        # Load configuration
        self.api_key = os.getenv('HOSTINGER_API_KEY')
        self.dashboard_url = os.getenv('DASHBOARD_URL', 'http://72.60.25.24:8080')
        
        if not self.api_key:
            raise ValueError("HOSTINGER_API_KEY environment variable not set")
        
        # Elasticsearch connection
        self.es = Elasticsearch(['http://localhost:9200'])
        
        # Filtering and rate limiting configuration
        self.config = {
            'min_threat_score': 0.3,
            'max_requests_per_minute': 2,  # Reduced from 10 to avoid 429 errors
            'dedup_window_seconds': 300,  # 5 minutes
            'batch_size': 50,  # Increased to batch more threats
            'compression_threshold': 5,  # Compress if > 5 items
            'rate_limits': {
                'weak_security': {'max_per_hour': 5, 'count': 0, 'reset_time': None},
                'hidden_ssid': {'max_per_hour': 3, 'count': 0, 'reset_time': None},
                'evil_twin_same_ssid': {'max_per_hour': 10, 'count': 0, 'reset_time': None},
                'beacon_flooding': {'max_per_hour': 5, 'count': 0, 'reset_time': None},
                'deauth_attack': {'max_per_hour': 5, 'count': 0, 'reset_time': None}
            }
        }
        
        # Exponential backoff for rate limiting
        self.backoff_time = 30  # Start with 30 seconds
        self.max_backoff = 300  # Max 5 minutes
        self.consecutive_429_errors = 0
        
        # State tracking
        self.threat_dedup = {}  # hash -> timestamp
        self.request_times = deque()  # For rate limiting
        self.aggregated_threats = defaultdict(list)
        self.last_successful_sync = None
        
        logger.info("🚀 Starting Filtered Hostinger Data Forwarder...")
        logger.info(f"📡 Dashboard URL: {self.dashboard_url}")
        logger.info(f"⚙️ Min threat score: {self.config['min_threat_score']}")
        logger.info(f"⏱️ Max requests/min: {self.config['max_requests_per_minute']}")
    
    def create_threat_hash(self, threat):
        """Create unique hash for threat deduplication"""
        # Create hash from key threat characteristics
        key_data = {
            'source': threat.get('source', ''),
            'detection_type': threat.get('detection_type', ''),
            'threat_score': round(threat.get('threat_score', 0), 1),
            'threats_detected': sorted(threat.get('threats_detected', [])),
            'network_bssid': threat.get('network_info', {}).get('bssid', '')
        }
        
        hash_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(hash_string.encode()).hexdigest()
    
    def is_duplicate_threat(self, threat_hash):
        """Check if threat is a recent duplicate"""
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.config['dedup_window_seconds'])
        
        # Clean old entries
        old_hashes = [h for h, ts in self.threat_dedup.items() if ts < cutoff]
        for h in old_hashes:
            del self.threat_dedup[h]
        
        # Check if current threat is duplicate
        if threat_hash in self.threat_dedup:
            return True
        
        self.threat_dedup[threat_hash] = now
        return False
    
    def should_rate_limit_threat(self, threat_types):
        """Check if threat should be rate limited"""
        now = datetime.utcnow()
        current_hour = now.hour
        
        for threat_type in threat_types:
            if threat_type in self.config['rate_limits']:
                limit_info = self.config['rate_limits'][threat_type]
                
                # Reset counter if new hour
                if limit_info['reset_time'] != current_hour:
                    limit_info['count'] = 0
                    limit_info['reset_time'] = current_hour
                
                # Check if over limit
                if limit_info['count'] >= limit_info['max_per_hour']:
                    return True
                
                # Increment counter
                limit_info['count'] += 1
        
        return False
    
    def filter_threat(self, threat):
        """Apply filtering logic to determine if threat should be forwarded"""
        # Check threat score threshold
        threat_score = threat.get('threat_score', 0)
        if threat_score < self.config['min_threat_score']:
            return False, f"Low threat score: {threat_score}"
        
        # Check for duplicates
        threat_hash = self.create_threat_hash(threat)
        if self.is_duplicate_threat(threat_hash):
            return False, "Duplicate threat"
        
        # Check rate limiting
        threat_types = threat.get('threats_detected', [])
        if self.should_rate_limit_threat(threat_types):
            return False, f"Rate limited: {threat_types}"
        
        # Additional filters for specific threat types
        source = threat.get('source', '')
        
        # WiFi-specific filters
        if source == 'wifi_threat_detector':
            network_info = threat.get('network_info', {})
            ssid = network_info.get('ssid', '').lower()
            
            # Skip common legitimate networks
            legitimate_patterns = ['eduroam', 'guest', 'visitor', 'free', 'public']
            if any(pattern in ssid for pattern in legitimate_patterns) and threat_score < 0.6:
                return False, f"Likely legitimate network: {ssid}"
            
            # Skip very weak signals (likely distant/irrelevant)
            try:
                signal = float(network_info.get('signal', 0))
                if signal < -80:  # Very weak signal
                    return False, f"Weak signal: {signal}dBm"
            except:
                pass
        
        # USB-specific filters  
        elif source in ['usb_keystroke_monitor', 'enhanced_usb_monitor', 'usb_advanced_threat_system', 'usb_monitor_enhanced']:
            # USB threats are high-value indicators, lower the threshold
            if threat_score < 0.2:  # Lower threshold for USB (normally 0.3)
                return False, f"Low USB threat score: {threat_score}"
            
            # Always forward keystroke threats regardless of score
            if source == 'usb_keystroke_monitor' or 'keystroke' in str(threat.get('detection_type', '')):
                return True, "USB keystroke threat (high priority)"
        
        # OpenCanary honeypot events - always forward
        elif source in ['opencanary', 'opencanary_forwarder', 'honeypot']:
            # Honeypot interactions are always important
            return True, "Honeypot interaction (high priority)"
        
        # BLE-specific filters
        elif source in ['ble_enhanced_detector', 'ble_detector']:
            # BLE threats are rare, so forward most of them
            # Filter out very weak BLE signals
            device_info = threat.get('device_info', {})
            rssi = device_info.get('rssi', 0)
            if rssi < -90:  # Very weak BLE signal
                return False, f"Weak BLE signal: {rssi}dBm"
        
        # AirDrop-specific filters
        elif source == 'airdrop_threat_detector':
            # AirDrop threats are rare and valuable, forward most
            service_info = threat.get('service_info', {})
            if not service_info:  # Skip empty service data
                return False, "Empty AirDrop service data"
        
        # OpenCanary-specific filters
        elif source == 'opencanary':
            logtype = threat.get('logtype', '')
            src_host = threat.get('src_host', '')
            
            # Skip localhost connections (internal monitoring)
            if src_host in ['127.0.0.1', 'localhost', '::1']:
                return False, f"Internal connection: {src_host}"
            
            # Skip very common scans unless high threat score
            common_scans = ['portscan.portscan', 'http.request']
            if logtype in common_scans and threat_score < 0.5:
                return False, f"Common scan with low score: {logtype}"
        
        return True, "Passed filters"
    
    def can_send_request(self):
        """Check if we can send a request (rate limiting)"""
        now = time.time()
        
        # Remove old timestamps
        cutoff = now - 60  # 1 minute
        while self.request_times and self.request_times[0] < cutoff:
            self.request_times.popleft()
        
        # Check if under limit
        if len(self.request_times) >= self.config['max_requests_per_minute']:
            return False
        
        self.request_times.append(now)
        return True
    
    def sanitize_threat_data(self, threats):
        """Sanitize threat data to ensure dashboard compatibility"""
        sanitized = []
        for threat in threats:
            # Create clean copy with essential fields only
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
                'dst_port': threat.get('dst_port')
            }
            
            # Remove None values to reduce payload size
            clean_threat = {k: v for k, v in clean_threat.items() if v is not None}
            sanitized.append(clean_threat)
        
        return sanitized

    def compress_data(self, data, data_type="threats"):
        """Compress data if it's large enough"""
        # Sanitize threat data before compression
        if data_type == "threats":
            data = self.sanitize_threat_data(data)
            
        data_str = json.dumps(data)
        
        if len(data_str) > 1000:  # Compress if > 1KB
            compressed = gzip.compress(data_str.encode())
            return {
                'type': data_type,
                'honeypot_id': 'rpi-honeypot-001',
                'compressed': True,
                'data': compressed.hex()
            }
        
        return {
            'type': data_type,
            'honeypot_id': 'rpi-honeypot-001',
            'compressed': False,
            'data': data
        }
    
    def aggregate_similar_threats(self, threats):
        """Aggregate similar threats to reduce dashboard noise"""
        aggregated = {}
        
        for threat in threats:
            # Create aggregation key
            agg_key = f"{threat.get('source', '')}_{threat.get('detection_type', '')}"
            
            if agg_key not in aggregated:
                aggregated[agg_key] = {
                    'id': f"{int(time.time() * 1000)}-{hash(agg_key) % 10000}",
                    'timestamp': threat.get('timestamp'),
                    'honeypot_id': threat.get('honeypot_id', 'honeyman-01'),
                    'source': threat.get('source'),
                    'log_type': threat.get('log_type'),
                    'detection_type': threat.get('detection_type'),
                    'threat_score': threat.get('threat_score', 0),
                    'threats_detected': set(threat.get('threats_detected', [])),
                    'network_info': threat.get('network_info', {}),
                    'message': threat.get('message', ''),
                    'occurrence_count': 1,
                    'similar_threats': [threat]
                }
            else:
                # Aggregate with existing
                existing = aggregated[agg_key]
                existing['occurrence_count'] += 1
                existing['threat_score'] = max(existing['threat_score'], threat.get('threat_score', 0))
                existing['threats_detected'].update(threat.get('threats_detected', []))
                existing['similar_threats'].append(threat)
                
                # Update timestamp to most recent
                if threat.get('timestamp', '') > existing.get('timestamp', ''):
                    existing['timestamp'] = threat.get('timestamp')
        
        # Convert sets back to lists
        for threat in aggregated.values():
            threat['threats_detected'] = list(threat['threats_detected'])
            # Remove similar_threats from final payload to save space
            del threat['similar_threats']
        
        return list(aggregated.values())
    
    def fetch_and_filter_threats(self):
        """Fetch threats from Elasticsearch and apply filtering"""
        try:
            # Query for recent threats
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "timestamp": {
                                        "gte": "now-2m"  # Last 2 minutes
                                    }
                                }
                            }
                        ],
                        "must_not": [
                            {
                                "term": {
                                    "forwarded": True
                                }
                            }
                        ]
                    }
                },
                "size": 100,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            response = self.es.search(index="honeypot-logs-new", body=query)
            raw_threats = [hit['_source'] for hit in response['hits']['hits']]
            
            if not raw_threats:
                return [], []
            
            # Apply filtering
            filtered_threats = []
            filter_stats = defaultdict(int)
            
            for threat in raw_threats:
                should_forward, reason = self.filter_threat(threat)
                
                if should_forward:
                    filtered_threats.append(threat)
                else:
                    filter_stats[reason] += 1
            
            # Log filtering results
            if filter_stats:
                logger.info(f"🔍 Filtered {sum(filter_stats.values())} threats:")
                for reason, count in filter_stats.items():
                    logger.info(f"   - {reason}: {count}")
            
            # Aggregate similar threats
            if len(filtered_threats) > self.config['compression_threshold']:
                aggregated_threats = self.aggregate_similar_threats(filtered_threats)
                logger.info(f"📦 Aggregated {len(filtered_threats)} threats into {len(aggregated_threats)} items")
                return aggregated_threats, raw_threats
            
            return filtered_threats, raw_threats
            
        except Exception as e:
            logger.error(f"❌ Error fetching threats: {e}")
            return [], []
    
    def send_to_dashboard(self, threats, data_type="threats"):
        """Send filtered threats to dashboard with rate limiting"""
        if not threats:
            return True
        
        if not self.can_send_request():
            logger.warning(f"⚠️ Rate limit reached, skipping {data_type} upload")
            return False
        
        try:
            # Prepare payload
            payload = self.compress_data(threats, data_type)
            
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
                logger.info(f"✅ Successfully sent {len(threats)} {data_type} to dashboard")
                self.last_successful_sync = datetime.utcnow()
                self.consecutive_429_errors = 0  # Reset backoff on success
                self.backoff_time = 30  # Reset to initial backoff
                return True
            elif response.status_code == 429:
                self.consecutive_429_errors += 1
                logger.warning(f"⚠️ Dashboard rate limit hit (429) - backing off for {self.backoff_time}s")
                time.sleep(self.backoff_time)
                # Exponential backoff
                self.backoff_time = min(self.backoff_time * 2, self.max_backoff)
                return False
            else:
                logger.error(f"❌ Dashboard API error: {response.status_code}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error(f"⏱️ Timeout sending {data_type} to dashboard")
            return False
        except Exception as e:
            logger.error(f"❌ Error sending {data_type} to dashboard: {e}")
            return False
    
    def get_system_status(self):
        """Get system status information with filtering stats"""
        try:
            # Get Elasticsearch stats
            es_health = self.es.cluster.health()
            
            # Count recent threats by type
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": "now-1h"
                        }
                    }
                },
                "aggs": {
                    "by_source": {
                        "terms": {
                            "field": "source.keyword",
                            "size": 10
                        }
                    },
                    "by_threat_score": {
                        "histogram": {
                            "field": "threat_score",
                            "interval": 0.2
                        }
                    }
                },
                "size": 0
            }
            
            response = self.es.search(index="honeypot-logs-new", body=query)
            
            status = {
                'timestamp': datetime.utcnow().isoformat(),
                'honeypot_id': 'honeyman-01',
                'elasticsearch_status': es_health.get('status', 'unknown'),
                'total_threats_last_hour': response['hits']['total']['value'],
                'threat_sources': {
                    bucket['key']: bucket['doc_count'] 
                    for bucket in response['aggregations']['by_source']['buckets']
                },
                'threat_score_distribution': {
                    f"{bucket['key']}-{bucket['key']+0.2}": bucket['doc_count']
                    for bucket in response['aggregations']['by_threat_score']['buckets']
                },
                'filtering_stats': {
                    'dedup_cache_size': len(self.threat_dedup),
                    'rate_limit_stats': {
                        k: v['count'] for k, v in self.config['rate_limits'].items()
                    },
                    'last_successful_sync': self.last_successful_sync.isoformat() if self.last_successful_sync else None
                },
                'services': {
                    'forwarder': 'running',
                    'elasticsearch': es_health.get('status', 'unknown')
                }
            }
            
            return status
            
        except Exception as e:
            logger.error(f"❌ Error getting system status: {e}")
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'honeypot_id': 'honeyman-01',
                'services': {'forwarder': 'running', 'elasticsearch': 'error'},
                'error': str(e)
            }
    
    def run(self):
        """Main forwarder loop with filtering"""
        logger.info("🚀 Starting filtered data forwarder loop...")
        
        while True:
            try:
                # Fetch and filter threats
                threats, raw_threats = self.fetch_and_filter_threats()
                
                if threats:
                    logger.info(f"📤 Prepared threats payload: {len(threats)} items (filtered from {len(raw_threats)})")
                    success = self.send_to_dashboard(threats, "threats")
                    
                    if success:
                        # Mark threats as forwarded in Elasticsearch
                        for threat in raw_threats:
                            try:
                                # This would require storing document IDs, simplified for now
                                pass
                            except:
                                pass
                
                # Send system status every other cycle
                if int(time.time()) % 60 < 30:  # Every minute, first 30 seconds
                    status = self.get_system_status()
                    logger.info(f"📊 Prepared status payload: {len(status)} items")
                    self.send_to_dashboard([status], "status")
                
                # Clean up old tracking data
                if int(time.time()) % 300 == 0:  # Every 5 minutes
                    self.cleanup_tracking_data()
                
                # Wait before next iteration (increased to reduce API calls)
                time.sleep(60)  # Increased from 30s to 60s
                
            except KeyboardInterrupt:
                logger.info("🛑 Forwarder stopped by user")
                break
            except Exception as e:
                logger.error(f"❌ Unexpected error in forwarder loop: {e}")
                time.sleep(30)
    
    def cleanup_tracking_data(self):
        """Clean up old tracking data to prevent memory leaks"""
        now = datetime.utcnow()
        
        # Clean deduplication cache
        cutoff = now - timedelta(seconds=self.config['dedup_window_seconds'] * 2)
        old_hashes = [h for h, ts in self.threat_dedup.items() if ts < cutoff]
        for h in old_hashes:
            del self.threat_dedup[h]
        
        logger.info(f"🧹 Cleaned {len(old_hashes)} old threat hashes from cache")

if __name__ == "__main__":
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    try:
        forwarder = FilteredDataForwarder()
        forwarder.run()
    except KeyboardInterrupt:
        logger.info("🛑 Forwarder stopped")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")