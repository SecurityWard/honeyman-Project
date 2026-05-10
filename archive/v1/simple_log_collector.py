#!/usr/bin/env python3
"""
Simple Log Collector - Works without permission issues
"""
import time
import subprocess
import json
import os
from datetime import datetime
from pathlib import Path

class SimpleLogCollector:
    def __init__(self):
        self.log_dir = Path("logs")
        self.log_dir.mkdir(exist_ok=True)
        
    def collect_container_logs(self):
        """Collect logs from containers and save locally"""
        containers = ['honeypot-opencanary', 'honeypot-web', 'honeypot-elasticsearch']
        
        for container in containers:
            try:
                # Get recent logs
                result = subprocess.run(
                    ['docker', 'logs', '--tail', '50', container],
                    capture_output=True,
                    text=True
                )
                
                if result.stdout:
                    # Save to file
                    log_file = self.log_dir / f"{container}-collected.log"
                    with open(log_file, 'a') as f:
                        f.write(f"\n--- {datetime.now().isoformat()} ---\n")
                        f.write(result.stdout)
                        
                    print(f"✅ Collected logs from {container}")
                    
            except Exception as e:
                print(f"❌ Failed to collect from {container}: {e}")
                
    def send_to_elasticsearch(self):
        """Send collected logs to Elasticsearch"""
        try:
            import requests
            
            for log_file in self.log_dir.glob("*-collected.log"):
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    
                # Send recent lines
                for line in lines[-10:]:  # Last 10 lines
                    if line.strip() and not line.startswith('---'):
                        doc = {
                            'timestamp': datetime.utcnow().isoformat(),
                            'source': log_file.stem.replace('-collected', ''),
                            'message': line.strip(),
                            'log_type': 'honeypot-manual'
                        }
                        
                        # Send to Elasticsearch
                        response = requests.post(
                            'http://localhost:9200/honeypot-logs/_doc',
                            json=doc,
                            timeout=5
                        )
                        
                        if response.status_code in [200, 201]:
                            print(f"✅ Sent log entry to Elasticsearch")
                        
        except ImportError:
            print("📦 Install requests: pip3 install requests")
        except Exception as e:
            print(f"❌ Elasticsearch error: {e}")

if __name__ == "__main__":
    collector = SimpleLogCollector()
    
    print("📊 Collecting container logs...")
    collector.collect_container_logs()
    
    print("📤 Sending to Elasticsearch...")
    collector.send_to_elasticsearch()
    
    print("✅ Log collection complete")
