#!/usr/bin/env python3
"""
Honeypot Log Management and Filtering System
Manages log rotation, filtering, and aggregation across all detection modules
"""

import os
import gzip
import json
import time
import shutil
import logging
from datetime import datetime, timedelta
from pathlib import Path
import re

class HoneypotLogManager:
    def __init__(self, log_dir="/home/burner/honeypot-minimal/logs"):
        self.log_dir = Path(log_dir)
        self.config_file = Path("/home/burner/honeypot-minimal/log_config.json")
        
        # Default configuration
        self.config = {
            "max_log_size_mb": 50,
            "max_log_files": 5,
            "compression_enabled": True,
            "log_levels": {
                "wifi_threat": "INFO",
                "usb_threat": "INFO", 
                "ble_threat": "INFO",
                "multi_vector": "INFO",
                "advanced_wireless": "INFO"
            },
            "noise_filters": {
                "duplicate_threshold_seconds": 300,
                "min_threat_score": 0.3,
                "exclude_patterns": [
                    "RequestsDependencyWarning",
                    "urllib3.*doesn't match",
                    "charset_normalizer",
                    "Starting.*Detection System"
                ],
                "whitelist_ssids": [
                    "eduroam",
                    "Guest Network", 
                    "Visitor"
                ],
                "rate_limit_per_hour": {
                    "weak_security": 5,
                    "hidden_ssid": 3,
                    "suspicious_ssid": 10
                }
            }
        }
        
        self.load_config()
        self.threat_counts = {}  # Track threat frequency
        self.recent_threats = {}  # Deduplication tracking
        
    def load_config(self):
        """Load configuration from file or create default"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    saved_config = json.load(f)
                    # Merge with defaults
                    self.config.update(saved_config)
                print(f"📋 Loaded log management config from {self.config_file}")
            else:
                self.save_config()
                print(f"📋 Created default log management config at {self.config_file}")
        except Exception as e:
            print(f"⚠️ Error loading log config: {e}, using defaults")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"❌ Error saving log config: {e}")
    
    def setup_logging(self, module_name):
        """Setup filtered logging for a detection module"""
        log_level = getattr(logging, self.config["log_levels"].get(module_name, "INFO"))
        
        # Create custom formatter that filters noise
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Setup file handler with rotation
        log_file = self.log_dir / f"{module_name}_filtered.log"
        handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.config["max_log_size_mb"] * 1024 * 1024,
            backupCount=self.config["max_log_files"]
        )
        handler.setFormatter(formatter)
        
        # Create logger
        logger = logging.getLogger(f"honeypot.{module_name}")
        logger.setLevel(log_level)
        logger.addHandler(handler)
        
        # Add noise filter
        logger.addFilter(self.create_noise_filter())
        
        return logger
    
    def create_noise_filter(self):
        """Create a logging filter to reduce noise"""
        class NoiseFilter(logging.Filter):
            def __init__(self, manager):
                super().__init__()
                self.manager = manager
                
            def filter(self, record):
                message = record.getMessage()
                
                # Filter out excluded patterns
                for pattern in self.manager.config["noise_filters"]["exclude_patterns"]:
                    if re.search(pattern, message, re.IGNORECASE):
                        return False
                
                # Rate limiting for common threat types
                if hasattr(record, 'threat_type'):
                    threat_type = record.threat_type
                    limit = self.manager.config["noise_filters"]["rate_limit_per_hour"].get(threat_type, float('inf'))
                    
                    current_hour = datetime.now().hour
                    key = f"{threat_type}_{current_hour}"
                    
                    if key not in self.manager.threat_counts:
                        self.manager.threat_counts[key] = 0
                    
                    self.manager.threat_counts[key] += 1
                    
                    if self.manager.threat_counts[key] > limit:
                        return False
                
                return True
        
        return NoiseFilter(self)
    
    def rotate_logs(self):
        """Manually rotate and compress old logs"""
        print("🔄 Starting log rotation...")
        
        for log_file in self.log_dir.glob("*.log"):
            if log_file.stat().st_size > self.config["max_log_size_mb"] * 1024 * 1024:
                print(f"📦 Rotating large log file: {log_file.name}")
                self.rotate_single_log(log_file)
        
        # Clean old compressed logs
        self.cleanup_old_logs()
        
    def rotate_single_log(self, log_file):
        """Rotate a single log file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated_name = f"{log_file.stem}_{timestamp}.log"
            rotated_path = self.log_dir / rotated_name
            
            # Copy current log to rotated name
            shutil.copy2(log_file, rotated_path)
            
            # Compress if enabled
            if self.config["compression_enabled"]:
                compressed_path = rotated_path.with_suffix(".log.gz")
                with open(rotated_path, 'rb') as f_in:
                    with gzip.open(compressed_path, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                rotated_path.unlink()  # Remove uncompressed version
                print(f"📦 Compressed {rotated_name} -> {compressed_path.name}")
            
            # Truncate original log
            with open(log_file, 'w') as f:
                f.write(f"# Log rotated at {datetime.now()}\n")
                
        except Exception as e:
            print(f"❌ Error rotating {log_file}: {e}")
    
    def cleanup_old_logs(self):
        """Remove old compressed logs beyond retention limit"""
        compressed_logs = list(self.log_dir.glob("*.log.gz"))
        
        # Group by base name
        log_groups = {}
        for log_file in compressed_logs:
            base_name = log_file.name.split('_')[0]
            if base_name not in log_groups:
                log_groups[base_name] = []
            log_groups[base_name].append(log_file)
        
        # Keep only the newest files for each log type
        for base_name, files in log_groups.items():
            files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            to_remove = files[self.config["max_log_files"]:]
            
            for old_file in to_remove:
                print(f"🗑️ Removing old log: {old_file.name}")
                old_file.unlink()
    
    def filter_elasticsearch_logs(self):
        """Filter and deduplicate threats going to Elasticsearch"""
        print("🔍 Filtering Elasticsearch logs...")
        
        # This would integrate with the data forwarder to filter before sending
        # For now, we'll create a filtered version of recent logs
        
        try:
            import requests
            
            # Query recent logs from Elasticsearch
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": "now-1h"
                        }
                    }
                },
                "size": 1000,
                "sort": [{"timestamp": {"order": "desc"}}]
            }
            
            response = requests.post(
                'http://localhost:9200/honeypot-logs/_search',
                json=query,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                hits = data.get('hits', {}).get('hits', [])
                
                filtered_count = 0
                duplicate_count = 0
                
                for hit in hits:
                    source = hit['_source']
                    
                    # Apply threat score filter
                    threat_score = source.get('threat_score', 0)
                    if threat_score < self.config["noise_filters"]["min_threat_score"]:
                        filtered_count += 1
                        continue
                    
                    # Check for duplicates
                    threat_key = f"{source.get('source', '')}:{source.get('message', '')}"
                    if self.is_duplicate_threat(threat_key):
                        duplicate_count += 1
                        continue
                
                print(f"📊 Elasticsearch filter results:")
                print(f"   - {filtered_count} low-score threats filtered")
                print(f"   - {duplicate_count} duplicate threats filtered")
                print(f"   - {len(hits) - filtered_count - duplicate_count} legitimate threats")
                
        except Exception as e:
            print(f"❌ Error filtering Elasticsearch logs: {e}")
    
    def is_duplicate_threat(self, threat_key):
        """Check if threat is a recent duplicate"""
        now = datetime.now()
        threshold = timedelta(seconds=self.config["noise_filters"]["duplicate_threshold_seconds"])
        
        if threat_key in self.recent_threats:
            last_seen = self.recent_threats[threat_key]
            if now - last_seen < threshold:
                return True
        
        self.recent_threats[threat_key] = now
        return False
    
    def generate_log_report(self):
        """Generate a summary report of log activity"""
        print("\n📊 Honeypot Log Summary Report")
        print("=" * 50)
        
        # Analyze log files
        total_size = 0
        file_count = 0
        
        for log_file in self.log_dir.glob("*.log"):
            size_mb = log_file.stat().st_size / (1024 * 1024)
            total_size += size_mb
            file_count += 1
            
            print(f"📄 {log_file.name}: {size_mb:.2f} MB")
        
        # Count compressed logs
        compressed_count = len(list(self.log_dir.glob("*.log.gz")))
        
        print(f"\n📊 Summary:")
        print(f"   - Active log files: {file_count}")
        print(f"   - Compressed archives: {compressed_count}")
        print(f"   - Total size: {total_size:.2f} MB")
        
        # Threat frequency analysis
        if self.threat_counts:
            print(f"\n⚡ Threat Frequency (current hour):")
            for threat_type, count in sorted(self.threat_counts.items()):
                print(f"   - {threat_type}: {count} alerts")
    
    def run_maintenance(self):
        """Run log maintenance tasks"""
        print("🔧 Running log maintenance...")
        
        # Rotate large logs
        self.rotate_logs()
        
        # Filter recent threats
        self.filter_elasticsearch_logs()
        
        # Clean up threat tracking
        self.cleanup_threat_tracking()
        
        # Generate report
        self.generate_log_report()
        
        print("✅ Log maintenance completed")
    
    def cleanup_threat_tracking(self):
        """Clean up old threat tracking data"""
        cutoff = datetime.now() - timedelta(hours=1)
        
        # Clean recent threats
        old_keys = [k for k, v in self.recent_threats.items() if v < cutoff]
        for key in old_keys:
            del self.recent_threats[key]
        
        # Clean hourly threat counts for previous hours
        current_hour = datetime.now().hour
        old_hour_keys = [k for k in self.threat_counts.keys() 
                        if not k.endswith(f"_{current_hour}")]
        for key in old_hour_keys:
            del self.threat_counts[key]
    
    def start_monitoring(self):
        """Start continuous log monitoring"""
        print("🔍 Starting log monitoring...")
        print("💡 Monitoring log sizes and performing maintenance")
        print("🛑 Press Ctrl+C to stop")
        
        try:
            while True:
                # Run maintenance every 10 minutes
                self.run_maintenance()
                
                # Wait
                time.sleep(600)  # 10 minutes
                
        except KeyboardInterrupt:
            print("\n🛑 Log monitoring stopped")

if __name__ == "__main__":
    manager = HoneypotLogManager()
    
    import sys
    if len(sys.argv) > 1:
        command = sys.argv[1]
        if command == "rotate":
            manager.rotate_logs()
        elif command == "filter":
            manager.filter_elasticsearch_logs()
        elif command == "report":
            manager.generate_log_report()
        elif command == "maintenance":
            manager.run_maintenance()
        elif command == "monitor":
            manager.start_monitoring()
        else:
            print("Usage: log_manager.py [rotate|filter|report|maintenance|monitor]")
    else:
        manager.run_maintenance()